from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.db.models import Incident, Tenant
from aegis_soar.tenancy.context import pre_auth_session, tenant_transaction


async def test_g1_negative_meta_role_is_non_superuser_and_nobypassrls(
    app_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G1 Negative Meta-Test: prove CI/pytest runs as aegis_app (NOT superuser/BYPASSRLS)."""
    async with pre_auth_session(app_session_factory) as session:
        row = (
            await session.execute(
                text(
                    "SELECT rolname, rolsuper, rolbypassrls "
                    "FROM pg_roles WHERE rolname = current_user"
                )
            )
        ).one()
        assert row.rolname == "aegis_app"
        assert row.rolsuper is False
        assert row.rolbypassrls is False


async def test_g1_fail_closed_and_cross_tenant_isolation(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G1: Verify fail-closed RLS (unset -> 0 rows) and strict cross-tenant isolation."""
    tenant_a: UUID = uuid4()
    tenant_b: UUID = uuid4()
    inc_a: UUID = uuid4()
    inc_b: UUID = uuid4()

    # Seed tenants first, flush to satisfy FK deterministically, then seed incidents
    async with owner_session_factory() as owner_sess, owner_sess.begin():
        owner_sess.add_all(
            [
                Tenant(
                    tenant_id=tenant_a, name="G1 Alpha", blast_radius_k_max=3, created_at=1700000000
                ),
                Tenant(
                    tenant_id=tenant_b, name="G1 Beta", blast_radius_k_max=3, created_at=1700000000
                ),
            ]
        )
        await owner_sess.flush()
        owner_sess.add_all(
            [
                Incident(
                    incident_id=inc_a,
                    tenant_id=tenant_a,
                    idempotency_key=f"g1-a-{inc_a}",
                    mitre_technique_id="T1110",
                    severity="HIGH",
                    triage_summary_untrusted="alpha",
                    created_at=1700000000,
                ),
                Incident(
                    incident_id=inc_b,
                    tenant_id=tenant_b,
                    idempotency_key=f"g1-b-{inc_b}",
                    mitre_technique_id="T1110",
                    severity="HIGH",
                    triage_summary_untrusted="beta",
                    created_at=1700000000,
                ),
            ]
        )

    try:
        # 1. Fail-closed: pre_auth_session (no set_config) MUST return 0 rows
        async with pre_auth_session(app_session_factory) as session:
            unset_rows = (await session.execute(select(Incident))).scalars().all()
            assert unset_rows == []

        # 2. Cross-tenant isolation: Tenant A bound -> 0 Tenant B rows even WITHOUT WHERE clause
        async with tenant_transaction(app_session_factory, tenant_a) as session:
            visible_rows = (await session.execute(select(Incident))).scalars().all()
            visible_ids = {r.incident_id for r in visible_rows}
            assert inc_a in visible_ids
            assert inc_b not in visible_ids
            assert all(r.tenant_id == tenant_a for r in visible_rows)
    finally:
        # Clean up seeded test fixtures as aegis_owner
        async with owner_session_factory() as owner_sess, owner_sess.begin():
            await owner_sess.execute(
                text("DELETE FROM incidents WHERE incident_id IN (:a, :b)"),
                {"a": inc_a, "b": inc_b},
            )
            await owner_sess.execute(
                text("DELETE FROM tenants WHERE tenant_id IN (:a, :b)"),
                {"a": tenant_a, "b": tenant_b},
            )
