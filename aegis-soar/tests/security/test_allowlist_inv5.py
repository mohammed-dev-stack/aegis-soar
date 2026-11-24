from __future__ import annotations

from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.adapters.simulated import SimulatedResponseAdapter
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
    ProtectedAsset,
    ResponseAction,
    Tenant,
    User,
    UserRole,
)
from aegis_soar.response.service import AllowlistViolationError, ResponseService
from aegis_soar.tenancy.context import tenant_transaction

NOW_UTC = 1700030000


async def test_g3_ipv4_mapped_rejected_and_zero_toctou_allowlist(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G3 (INV-5): ::ffff:0:0/96 rejected; late allowlist blocks approve."""
    priv, pub = generate_ed25519_keypair()
    kek = generate_mfa_kek()
    auth = AuthService(
        session_factory=app_session_factory,
        jwt_private_key=priv,
        jwt_public_key=pub,
        mfa_kek=kek,
    )
    svc = ResponseService(
        session_factory=app_session_factory,
        auth_service=auth,
        adapter=SimulatedResponseAdapter(),
    )

    tenant_id = uuid4()
    admin_id = uuid4()
    analyst_id = uuid4()
    approver_id = uuid4()
    incident_id = uuid4()
    action_id = uuid4()
    totp_secret = generate_totp_base32_secret()

    async with owner_session_factory() as sess, sess.begin():
        sess.add(
            Tenant(tenant_id=tenant_id, name="G3 INV5", blast_radius_k_max=5, created_at=NOW_UTC)
        )
        await sess.flush()
        sess.add_all(
            [
                User(
                    user_id=admin_id,
                    tenant_id=tenant_id,
                    email=f"admin-{admin_id}@inv5.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.TENANT_ADMIN,
                    created_at=NOW_UTC,
                ),
                User(
                    user_id=analyst_id,
                    tenant_id=tenant_id,
                    email=f"analyst-{analyst_id}@inv5.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.ANALYST,
                    created_at=NOW_UTC,
                ),
                User(
                    user_id=approver_id,
                    tenant_id=tenant_id,
                    email=f"approver-{approver_id}@inv5.test",
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
                    mitre_technique_id="T1110",
                    severity="HIGH",
                    created_at=NOW_UTC,
                ),
            ]
        )

    # 1. DB CHECK constraint rejects ::ffff:10.0.0.5
    with pytest.raises(IntegrityError):
        async with tenant_transaction(app_session_factory, tenant_id) as sess:
            sess.add(
                ResponseAction(
                    action_id=uuid4(),
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    idempotency_key="mapped-ipv6",
                    action_type=ActionType.FIREWALL_BLOCK_IP,
                    target_ip="::ffff:10.0.0.5",
                    state=ActionState.PENDING_APPROVAL,
                    ttl_seconds=300,
                    approval_expires_at=NOW_UTC + 3600,
                    proposed_by=analyst_id,
                    created_at=NOW_UTC,
                    updated_at=NOW_UTC,
                )
            )

    # 2. Propose action BEFORE CIDR is protected, then add CIDR, then approve -> trigger blocks!
    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        sess.add(
            ResponseAction(
                action_id=action_id,
                tenant_id=tenant_id,
                incident_id=incident_id,
                idempotency_key="toctou-target",
                action_type=ActionType.HOST_ISOLATE,
                target_ip="10.20.30.40",
                state=ActionState.PENDING_APPROVAL,
                ttl_seconds=300,
                approval_expires_at=NOW_UTC + 3600,
                proposed_by=analyst_id,
                created_at=NOW_UTC,
                updated_at=NOW_UTC,
            )
        )

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        sess.add(
            ProtectedAsset(
                asset_id=uuid4(),
                tenant_id=tenant_id,
                protected_cidr="10.20.30.0/24",
                label="Late-added DC Subnet",
                created_by=admin_id,
                created_at=NOW_UTC + 5,
            )
        )

    code = pyotp.TOTP(totp_secret).at(NOW_UTC + 10)
    with pytest.raises(AllowlistViolationError):
        await svc.approve_and_execute_action(
            tenant_id=tenant_id,
            action_id=action_id,
            approver_user_id=approver_id,
            totp_code=code,
            now_utc=NOW_UTC + 10,
        )

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        act = (
            await sess.execute(select(ResponseAction).where(ResponseAction.action_id == action_id))
        ).scalar_one()
        assert act.state == ActionState.PENDING_APPROVAL
