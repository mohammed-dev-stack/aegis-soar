from __future__ import annotations

from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.adapters.simulated import (
    AdapterState,
    SimulatedAdapterCrashError,
    SimulatedResponseAdapter,
)
from aegis_soar.auth.crypto import (
    encrypt_mfa_secret,
    generate_ed25519_keypair,
    generate_mfa_kek,
    generate_totp_base32_secret,
    hash_password,
)
from aegis_soar.auth.service import AuthService
from aegis_soar.db.models import (
    ActionState,
    ActionType,
    Incident,
    ResponseAction,
    Tenant,
    User,
    UserRole,
)
from aegis_soar.response.service import (
    STALE_EXECUTION_TIMEOUT_SECONDS,
    ResponseService,
)
from aegis_soar.tenancy.context import tenant_transaction

NOW_UTC = 1700050000


async def test_g5_crash_after_apply_reconciled_and_idempotent_rollback(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G5 (INV-7): Crash after adapter.apply reconciled to EXECUTED; rollback is idempotent."""
    priv, pub = generate_ed25519_keypair()
    kek = generate_mfa_kek()
    auth = AuthService(
        session_factory=app_session_factory,
        jwt_private_key=priv,
        jwt_public_key=pub,
        mfa_kek=kek,
    )
    adapter = SimulatedResponseAdapter()
    svc = ResponseService(
        session_factory=app_session_factory,
        auth_service=auth,
        adapter=adapter,
    )

    tenant_id = uuid4()
    analyst_id = uuid4()
    approver_id = uuid4()
    incident_id = uuid4()
    action_id = uuid4()
    totp_secret = generate_totp_base32_secret()

    async with owner_session_factory() as sess, sess.begin():
        sess.add(
            Tenant(tenant_id=tenant_id, name="G5 Reaper", blast_radius_k_max=5, created_at=NOW_UTC)
        )
        await sess.flush()
        sess.add_all(
            [
                User(
                    user_id=analyst_id,
                    tenant_id=tenant_id,
                    email=f"analyst-{analyst_id}@g5.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.ANALYST,
                    created_at=NOW_UTC,
                ),
                User(
                    user_id=approver_id,
                    tenant_id=tenant_id,
                    email=f"approver-{approver_id}@g5.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.APPROVER,
                    mfa_secret_enc=encrypt_mfa_secret(
                        kek=kek,
                        user_id=approver_id,
                        tenant_id=tenant_id,
                        base32_secret=totp_secret,
                    ),
                    created_at=NOW_UTC,
                ),
                Incident(
                    incident_id=incident_id,
                    tenant_id=tenant_id,
                    idempotency_key=f"inc-{incident_id}",
                    mitre_technique_id="T1059.004",
                    severity="CRITICAL",
                    created_at=NOW_UTC,
                ),
            ]
        )
        await sess.flush()
        sess.add(
            ResponseAction(
                action_id=action_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                idempotency_key=f"act-{action_id}",
                action_type=ActionType.HOST_ISOLATE,
                target_ip="198.51.100.99",
                state=ActionState.PENDING_APPROVAL,
                ttl_seconds=300,
                approval_expires_at=NOW_UTC + 3600,
                proposed_by=analyst_id,
                created_at=NOW_UTC,
                updated_at=NOW_UTC,
            )
        )

    # 1. Inject crash immediately after adapter.apply() succeeds (skipping Phase 3)
    adapter.crash_after_apply_ids.add(action_id)
    code1 = pyotp.TOTP(totp_secret).at(NOW_UTC)
    with pytest.raises(SimulatedAdapterCrashError):
        await svc.approve_and_execute_action(
            tenant_id=tenant_id,
            action_id=action_id,
            approver_user_id=approver_id,
            totp_code=code1,
            now_utc=NOW_UTC,
        )

    # Row is stuck in EXECUTING while adapter state is APPLIED
    assert await adapter.get_state(action_id) == AdapterState.APPLIED
    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        act = (
            await sess.execute(select(ResponseAction).where(ResponseAction.action_id == action_id))
        ).scalar_one()
        assert act.state == ActionState.EXECUTING

    # 2. Run stale EXECUTING reaper after timeout -> deterministically reconciles to EXECUTED
    reconciled_ids = await svc.reconcile_stale_executing(
        tenant_id=tenant_id,
        now_utc=NOW_UTC + STALE_EXECUTION_TIMEOUT_SECONDS + 5,
    )
    assert reconciled_ids == [action_id]

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        act = (
            await sess.execute(select(ResponseAction).where(ResponseAction.action_id == action_id))
        ).scalar_one()
        assert act.state == ActionState.EXECUTED
        assert act.expires_at == NOW_UTC + 300

    # 3. Rollback action with fresh TOTP step and verify adapter idempotency
    rollback_ts = NOW_UTC + 120
    code2 = pyotp.TOTP(totp_secret).at(rollback_ts)
    rolled = await svc.rollback_action(
        tenant_id=tenant_id,
        action_id=action_id,
        approver_user_id=approver_id,
        totp_code=code2,
        now_utc=rollback_ts,
    )
    assert rolled.state == ActionState.ROLLED_BACK
    assert await adapter.get_state(action_id) == AdapterState.ROLLED_BACK
    # Direct idempotent replay on adapter
    replay = await adapter.rollback(action_id)
    assert replay.state == AdapterState.ROLLED_BACK
    assert replay.detail == "idempotent_replay"
