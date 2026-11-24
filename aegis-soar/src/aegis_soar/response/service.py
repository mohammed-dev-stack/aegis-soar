from __future__ import annotations

from typing import Protocol
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.adapters.simulated import AdapterState, ResponseAdapter
from aegis_soar.audit.logger import append_audit_event
from aegis_soar.auth.service import AuthService, InsufficientRoleError
from aegis_soar.db.models import ActionState, ResponseAction, Tenant, UserRole
from aegis_soar.safety_limits.ip_guard import normalize_canonical_ip
from aegis_soar.tenancy.context import tenant_transaction

STALE_EXECUTION_TIMEOUT_SECONDS = 60


class ResponseError(Exception):
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"


class ActionNotFoundError(ResponseError):
    status_code = 404
    error_code = "ACTION_NOT_FOUND"


class InvalidStateTransitionError(ResponseError):
    status_code = 409
    error_code = "INVALID_STATE_TRANSITION"


class ActionExpiredError(ResponseError):
    status_code = 409
    error_code = "ACTION_EXPIRED"


class AllowlistViolationError(ResponseError):
    status_code = 422
    error_code = "ALLOWLIST_VIOLATION"


class BlastRadiusExceededError(ResponseError):
    status_code = 429
    error_code = "BLAST_RADIUS_EXCEEDED"


class AdapterExecutionError(ResponseError):
    status_code = 502
    error_code = "ADAPTER_EXECUTION_FAILED"


class LockStrategy(Protocol):
    """Injectable tenant blast-radius serialization strategy (INV-6)."""

    async def acquire_blast_lock(self, session: AsyncSession, tenant_id: UUID) -> None: ...


class PgAdvisoryBlastLock:
    """Production INV-6 lock: shared across HOST_ISOLATE and FIREWALL_BLOCK_IP."""

    async def acquire_blast_lock(self, session: AsyncSession, tenant_id: UUID) -> None:
        lock_key = f"{tenant_id}:blast"
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 0))"),
            {"lock_key": lock_key},
        )


class NoopLock:
    """Test-only lock strategy used exclusively by Gate G3's negative race-proof test."""

    async def acquire_blast_lock(self, session: AsyncSession, tenant_id: UUID) -> None:
        _ = (session, tenant_id)


def _translate_db_error(exc: DBAPIError) -> Exception:
    msg = str(exc.orig) if exc.orig is not None else str(exc)
    if "ALLOWLIST_VIOLATION" in msg:
        return AllowlistViolationError("Target IP is protected by tenant allowlist")
    if "INVALID_STATE_TRANSITION" in msg:
        return InvalidStateTransitionError("Illegal action state transition")
    if "INSUFFICIENT_ROLE" in msg or "chk_four_eyes" in msg:
        return InsufficientRoleError("Approver role or 4-eyes constraint violated")
    return exc


class ResponseService:
    """Two-phase containment execution, rollback, and crash reconciliation engine."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        auth_service: AuthService,
        adapter: ResponseAdapter,
        lock_strategy: LockStrategy | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._auth = auth_service
        self._adapter = adapter
        self._lock_strategy: LockStrategy = lock_strategy or PgAdvisoryBlastLock()

    async def approve_and_execute_action(
        self,
        *,
        tenant_id: UUID,
        action_id: UUID,
        approver_user_id: UUID,
        totp_code: str | None,
        now_utc: int,
    ) -> ResponseAction:
        """Execute Phase 1 (DB lock + slot reservation), Phase 2 (adapter), Phase 3 (DB commit)."""
        # ---------------------------------------------------------------------
        # Phase 1: Short DB transaction (zero external I/O)
        # ---------------------------------------------------------------------
        async with tenant_transaction(self._session_factory, tenant_id) as session:
            await self._lock_strategy.acquire_blast_lock(session, tenant_id)

            action = (
                await session.execute(
                    select(ResponseAction)
                    .where(ResponseAction.action_id == action_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if action is None:
                raise ActionNotFoundError("Action not found")

            if action.state != ActionState.PENDING_APPROVAL:
                raise InvalidStateTransitionError(
                    f"Action in state {action.state.value} cannot be approved"
                )

            if now_utc >= action.approval_expires_at:
                raise ActionExpiredError("Action approval window has expired")

            approver = await self._auth.verify_authoritative_role(
                session=session,
                user_id=approver_user_id,
                required_role=UserRole.APPROVER,
            )

            if action.proposed_by == approver.user_id:
                raise InsufficientRoleError("4-eyes violation: approver cannot equal proposer")

            await self._auth.verify_and_consume_totp(
                session=session,
                tenant_id=tenant_id,
                user=approver,
                totp_code=totp_code,
                now_utc=now_utc,
            )

            tenant = (
                await session.execute(select(Tenant).where(Tenant.tenant_id == tenant_id))
            ).scalar_one()

            active_count = int(
                (
                    await session.execute(
                        text(
                            """
                            SELECT COUNT(*)
                            FROM response_actions
                            WHERE tenant_id = :t
                              AND state IN ('EXECUTING', 'EXECUTED')
                              AND (expires_at IS NULL OR expires_at > :now_utc)
                            """
                        ),
                        {"t": tenant_id, "now_utc": now_utc},
                    )
                ).scalar_one()
            )
            if active_count >= tenant.blast_radius_k_max:
                raise BlastRadiusExceededError(
                    f"Active containment cap reached ({active_count}/{tenant.blast_radius_k_max})"
                )

            action.state = ActionState.EXECUTING
            action.approved_by = approver.user_id
            action.mfa_verified_at = now_utc
            action.slot_reserved_at = now_utc
            action.updated_at = now_utc

            try:
                await session.flush()
            except DBAPIError as exc:
                raise _translate_db_error(exc) from exc

            await append_audit_event(
                session=session,
                tenant_id=tenant_id,
                actor_user_id=approver.user_id,
                event_type="ACTION_EXECUTING",
                entity_type="response_action",
                entity_id=action.action_id,
                payload={
                    "action_type": action.action_type.value,
                    "target_ip": str(action.target_ip),
                },
                now_utc=now_utc,
            )

            action_type_str = action.action_type.value
            target_ip_obj = normalize_canonical_ip(str(action.target_ip))
            ttl_seconds = action.ttl_seconds

        # ---------------------------------------------------------------------
        # Phase 2: Lock-free external adapter call
        # ---------------------------------------------------------------------
        adapter_result = await self._adapter.apply(
            action_id=action_id,
            action_type=action_type_str,
            target_ip=target_ip_obj,
        )

        # ---------------------------------------------------------------------
        # Phase 3: Short DB commit (EXECUTED or FAILED)
        # ---------------------------------------------------------------------
        async with tenant_transaction(self._session_factory, tenant_id) as session:
            action = (
                await session.execute(
                    select(ResponseAction)
                    .where(ResponseAction.action_id == action_id)
                    .with_for_update()
                )
            ).scalar_one()

            if adapter_result.state == AdapterState.APPLIED:
                action.state = ActionState.EXECUTED
                action.expires_at = now_utc + ttl_seconds
                action.adapter_state_ref = adapter_result.ref
                action.updated_at = now_utc
                event_type = "ACTION_EXECUTED"
            else:
                action.state = ActionState.FAILED
                action.updated_at = now_utc
                event_type = "ACTION_FAILED"

            await append_audit_event(
                session=session,
                tenant_id=tenant_id,
                actor_user_id=approver_user_id,
                event_type=event_type,
                entity_type="response_action",
                entity_id=action.action_id,
                payload={"adapter_ref": adapter_result.ref, "detail": adapter_result.detail},
                now_utc=now_utc,
            )
            await session.flush()
            result_action = action

        if result_action.state == ActionState.FAILED:
            raise AdapterExecutionError("Containment adapter failed to apply action")

        return result_action

    async def rollback_action(
        self,
        *,
        tenant_id: UUID,
        action_id: UUID,
        approver_user_id: UUID,
        totp_code: str | None,
        now_utc: int,
    ) -> ResponseAction:
        """Two-phase manual rollback (EXECUTED -> ROLLING_BACK -> ROLLED_BACK) with TOTP."""
        async with tenant_transaction(self._session_factory, tenant_id) as session:
            action = (
                await session.execute(
                    select(ResponseAction)
                    .where(ResponseAction.action_id == action_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if action is None:
                raise ActionNotFoundError("Action not found")

            if action.state != ActionState.EXECUTED:
                raise InvalidStateTransitionError(
                    f"Action in state {action.state.value} cannot be rolled back"
                )

            approver = await self._auth.verify_authoritative_role(
                session=session,
                user_id=approver_user_id,
                required_role=UserRole.APPROVER,
            )
            await self._auth.verify_and_consume_totp(
                session=session,
                tenant_id=tenant_id,
                user=approver,
                totp_code=totp_code,
                now_utc=now_utc,
            )

            action.state = ActionState.ROLLING_BACK
            action.updated_at = now_utc
            await session.flush()

            await append_audit_event(
                session=session,
                tenant_id=tenant_id,
                actor_user_id=approver.user_id,
                event_type="ACTION_ROLLING_BACK",
                entity_type="response_action",
                entity_id=action.action_id,
                payload={},
                now_utc=now_utc,
            )

        adapter_result = await self._adapter.rollback(action_id)

        async with tenant_transaction(self._session_factory, tenant_id) as session:
            action = (
                await session.execute(
                    select(ResponseAction)
                    .where(ResponseAction.action_id == action_id)
                    .with_for_update()
                )
            ).scalar_one()

            if adapter_result.state == AdapterState.ROLLED_BACK:
                action.state = ActionState.ROLLED_BACK
                event_type = "ACTION_ROLLED_BACK"
            else:
                action.state = ActionState.FAILED
                event_type = "ACTION_ROLLBACK_FAILED"
            action.updated_at = now_utc

            await append_audit_event(
                session=session,
                tenant_id=tenant_id,
                actor_user_id=approver_user_id,
                event_type=event_type,
                entity_type="response_action",
                entity_id=action.action_id,
                payload={"detail": adapter_result.detail},
                now_utc=now_utc,
            )
            await session.flush()
            return action

    async def reconcile_stale_executing(
        self,
        *,
        tenant_id: UUID,
        now_utc: int,
        stale_timeout_seconds: int = STALE_EXECUTION_TIMEOUT_SECONDS,
    ) -> list[UUID]:
        """Reaper: query adapter.get_state(action_id) for stale EXECUTING rows and reconcile."""
        cutoff = now_utc - stale_timeout_seconds
        async with tenant_transaction(self._session_factory, tenant_id) as session:
            stale_rows = (
                await session.execute(
                    select(ResponseAction.action_id, ResponseAction.slot_reserved_at).where(
                        ResponseAction.state == ActionState.EXECUTING,
                        ResponseAction.slot_reserved_at.is_not(None),
                        ResponseAction.slot_reserved_at < cutoff,
                    )
                )
            ).all()

        reconciled: list[UUID] = []
        for row in stale_rows:
            action_id = UUID(str(row.action_id))
            adapter_state = await self._adapter.get_state(action_id)

            async with tenant_transaction(self._session_factory, tenant_id) as session:
                action = (
                    await session.execute(
                        select(ResponseAction)
                        .where(ResponseAction.action_id == action_id)
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                if action is None or action.state != ActionState.EXECUTING:
                    continue

                if adapter_state == AdapterState.APPLIED:
                    base_ts = action.slot_reserved_at or now_utc
                    action.state = ActionState.EXECUTED
                    action.expires_at = base_ts + action.ttl_seconds
                    action.adapter_state_ref = f"reconciled:{action.action_id}"
                    event_type = "ACTION_RECONCILED_EXECUTED"
                else:
                    action.state = ActionState.FAILED
                    event_type = "ACTION_RECONCILED_FAILED"
                action.updated_at = now_utc

                await append_audit_event(
                    session=session,
                    tenant_id=tenant_id,
                    actor_user_id=None,
                    event_type=event_type,
                    entity_type="response_action",
                    entity_id=action.action_id,
                    payload={"adapter_state": adapter_state.value},
                    now_utc=now_utc,
                )
                await session.flush()
                reconciled.append(action_id)

        return reconciled
