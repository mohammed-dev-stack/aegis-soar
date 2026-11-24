from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_soar.db.models import AuditLog

GENESIS_HASH = "0" * 64


def compute_event_hash(prev_hash: str, canonical_body: dict[str, Any]) -> str:
    """Compute SHA-256(prev_hash || canonical_json) for tamper-evident chaining."""
    serialized = json.dumps(canonical_body, sort_keys=True, separators=(",", ":"))
    digest_input = f"{prev_hash}:{serialized}".encode()
    return hashlib.sha256(digest_input).hexdigest()


async def append_audit_event(
    *,
    session: AsyncSession,
    tenant_id: UUID,
    actor_user_id: UUID | None,
    event_type: str,
    entity_type: str,
    entity_id: UUID | None,
    payload: dict[str, Any],
    now_utc: int,
) -> AuditLog:
    """Append a hash-chained audit_log row inside the active tenant_transaction (INV-8)."""
    prev_hash = (
        await session.execute(
            select(AuditLog.event_hash)
            .where(AuditLog.tenant_id == tenant_id)
            .order_by(AuditLog.audit_id.desc())
            .limit(1)
        )
    ).scalar_one_or_none() or GENESIS_HASH

    canonical_body: dict[str, Any] = {
        "tenant_id": str(tenant_id),
        "actor_user_id": str(actor_user_id) if actor_user_id is not None else None,
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": str(entity_id) if entity_id is not None else None,
        "payload": payload,
        "created_at": now_utc,
    }
    event_hash = compute_event_hash(prev_hash, canonical_body)

    entry = AuditLog(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        payload=payload,
        prev_hash=prev_hash,
        event_hash=event_hash,
        created_at=now_utc,
    )
    session.add(entry)
    await session.flush()
    return entry
