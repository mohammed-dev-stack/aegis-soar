from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.audit.logger import append_audit_event
from aegis_soar.db.models import Tenant
from aegis_soar.tenancy.context import tenant_transaction

NOW_UTC = 1700060000


async def test_g5_audit_log_immutability_as_app_and_owner(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G5 (INV-8): UPDATE, DELETE, TRUNCATE on audit_log fail as app & owner."""
    tenant_id = uuid4()
    async with owner_session_factory() as sess, sess.begin():
        sess.add(
            Tenant(
                tenant_id=tenant_id,
                name="G5 Audit",
                blast_radius_k_max=3,
                created_at=NOW_UTC,
            )
        )

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        entry = await append_audit_event(
            session=sess,
            tenant_id=tenant_id,
            actor_user_id=None,
            event_type="AUDIT_IMMUTABILITY_PROBE",
            entity_type="tenant",
            entity_id=tenant_id,
            payload={"ok": True},
            now_utc=NOW_UTC,
        )
        audit_id = entry.audit_id

    for stmt in (
        f"UPDATE audit_log SET event_type = 'TAMPERED' WHERE audit_id = {audit_id}",
        f"DELETE FROM audit_log WHERE audit_id = {audit_id}",
        "TRUNCATE TABLE audit_log",
    ):
        with pytest.raises(DBAPIError):
            async with tenant_transaction(app_session_factory, tenant_id) as sess:
                await sess.execute(text(stmt))

    for stmt in (
        f"UPDATE audit_log SET event_type = 'TAMPERED' WHERE audit_id = {audit_id}",
        f"DELETE FROM audit_log WHERE audit_id = {audit_id}",
        "TRUNCATE TABLE audit_log",
    ):
        with pytest.raises(DBAPIError) as exc_info:
            async with owner_session_factory() as sess, sess.begin():
                await sess.execute(text(stmt))
        assert "AUDIT_LOG_IMMUTABLE" in str(exc_info.value)
