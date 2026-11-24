from __future__ import annotations

import asyncio
from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.adapters.simulated import SimulatedResponseAdapter
from aegis_soar.auth.crypto import (
    encrypt_mfa_secret,
    generate_ed25519_keypair,
    generate_mfa_kek,
    generate_totp_base32_secret,
    hash_password,
)
from aegis_soar.auth.service import (
    AuthService,
    InvalidTotpError,
    MfaLockedError,
    TotpReplayError,
)
from aegis_soar.db.models import (
    ActionState,
    ActionType,
    Incident,
    ResponseAction,
    Tenant,
    User,
    UserRole,
)
from aegis_soar.response.service import ResponseService
from aegis_soar.tenancy.context import tenant_transaction

NOW_UTC = 1700020000


async def test_g2_concurrent_totp_replay_and_autonomous_lockout(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G2: Concurrent TOTP replay allows 1/2; 5 bad codes survive rollback -> 423 lockout."""
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
    action1_id = uuid4()
    action2_id = uuid4()
    action3_id = uuid4()
    totp_secret = generate_totp_base32_secret()
    totp_enc = encrypt_mfa_secret(
        kek=kek, user_id=approver_id, tenant_id=tenant_id, base32_secret=totp_secret
    )

    async with owner_session_factory() as sess, sess.begin():
        sess.add(
            Tenant(tenant_id=tenant_id, name="G2 MFA", blast_radius_k_max=5, created_at=NOW_UTC)
        )
        await sess.flush()
        sess.add_all(
            [
                User(
                    user_id=analyst_id,
                    tenant_id=tenant_id,
                    email=f"analyst-{analyst_id}@mfa.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.ANALYST,
                    created_at=NOW_UTC,
                ),
                User(
                    user_id=approver_id,
                    tenant_id=tenant_id,
                    email=f"approver-{approver_id}@mfa.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.APPROVER,
                    mfa_secret_enc=totp_enc,
                    created_at=NOW_UTC,
                ),
                Incident(
                    incident_id=incident_id,
                    tenant_id=tenant_id,
                    idempotency_key=f"inc-{incident_id}",
                    mitre_technique_id="T1110",
                    severity="HIGH",
                    created_at=NOW_UTC,
                ),
            ]
        )
        await sess.flush()
        sess.add_all(
            [
                ResponseAction(
                    action_id=aid,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    idempotency_key=f"act-{aid}",
                    action_type=ActionType.FIREWALL_BLOCK_IP,
                    target_ip=f"198.51.100.{idx}",
                    state=ActionState.PENDING_APPROVAL,
                    ttl_seconds=300,
                    approval_expires_at=NOW_UTC + 3600,
                    proposed_by=analyst_id,
                    created_at=NOW_UTC,
                    updated_at=NOW_UTC,
                )
                for idx, aid in enumerate((action1_id, action2_id, action3_id), start=10)
            ]
        )

    # 1. Concurrent TOTP replay: same valid code fired on 2 distinct actions -> 1 succeeds, 1 fails
    valid_code = pyotp.TOTP(totp_secret).at(NOW_UTC)
    results = await asyncio.gather(
        svc.approve_and_execute_action(
            tenant_id=tenant_id,
            action_id=action1_id,
            approver_user_id=approver_id,
            totp_code=valid_code,
            now_utc=NOW_UTC,
        ),
        svc.approve_and_execute_action(
            tenant_id=tenant_id,
            action_id=action2_id,
            approver_user_id=approver_id,
            totp_code=valid_code,
            now_utc=NOW_UTC,
        ),
        return_exceptions=True,
    )
    successes = [r for r in results if isinstance(r, ResponseAction)]
    replays = [r for r in results if isinstance(r, TotpReplayError)]
    assert len(successes) == 1
    assert len(replays) == 1

    # 2. Autonomous lockout: 5 invalid TOTP codes survive outer rollbacks -> 6th raises 423
    for offset in range(1, 6):
        with pytest.raises(InvalidTotpError):
            await svc.approve_and_execute_action(
                tenant_id=tenant_id,
                action_id=action3_id,
                approver_user_id=approver_id,
                totp_code="000000",
                now_utc=NOW_UTC + 60 + offset,
            )

    # Action3 MUST still be PENDING_APPROVAL (outer tx rolled back), but user MUST be locked
    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        act3 = (
            await sess.execute(select(ResponseAction).where(ResponseAction.action_id == action3_id))
        ).scalar_one()
        assert act3.state == ActionState.PENDING_APPROVAL

    fresh_valid_code = pyotp.TOTP(totp_secret).at(NOW_UTC + 120)
    with pytest.raises(MfaLockedError):
        await svc.approve_and_execute_action(
            tenant_id=tenant_id,
            action_id=action3_id,
            approver_user_id=approver_id,
            totp_code=fresh_valid_code,
            now_utc=NOW_UTC + 120,
        )
