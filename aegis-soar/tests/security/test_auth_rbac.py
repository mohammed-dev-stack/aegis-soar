from __future__ import annotations

from uuid import uuid4

import jwt
import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.auth.crypto import (
    decode_access_token,
    generate_ed25519_keypair,
    generate_mfa_kek,
    hash_password,
)
from aegis_soar.auth.service import (
    AuthService,
    InsufficientRoleError,
    RefreshTokenReuseError,
)
from aegis_soar.db.models import RefreshToken, Tenant, User, UserRole
from aegis_soar.tenancy.context import tenant_transaction

NOW_UTC = 1700010000


def test_g2_jwt_rejects_alg_none_and_hs256() -> None:
    """Gate G2: EdDSA verification strictly rejects alg=none and HS256 forged tokens."""
    _, pub = generate_ed25519_keypair()

    none_token = jwt.encode(
        {
            "sub": str(uuid4()),
            "tid": str(uuid4()),
            "jti": str(uuid4()),
            "iat": NOW_UTC,
            "exp": NOW_UTC + 300,
        },
        key="",
        algorithm="none",
    )
    with pytest.raises(jwt.InvalidAlgorithmError):
        decode_access_token(public_key=pub, token=none_token, now_utc=NOW_UTC)

    hs256_token = jwt.encode(
        {
            "sub": str(uuid4()),
            "tid": str(uuid4()),
            "jti": str(uuid4()),
            "iat": NOW_UTC,
            "exp": NOW_UTC + 300,
        },
        key="forged-hmac-secret-at-least-32-bytes-long!",
        algorithm="HS256",
    )
    with pytest.raises(jwt.InvalidAlgorithmError):
        decode_access_token(public_key=pub, token=hs256_token, now_utc=NOW_UTC)


async def test_g2_demoted_approver_rejected_and_refresh_reuse_revokes_family(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G2: DB-backed role demotion takes immediate effect; refresh reuse revokes family."""
    priv, pub = generate_ed25519_keypair()
    kek = generate_mfa_kek()
    auth = AuthService(
        session_factory=app_session_factory,
        jwt_private_key=priv,
        jwt_public_key=pub,
        mfa_kek=kek,
    )

    tenant_id = uuid4()
    user_id = uuid4()
    email = f"approver-{user_id}@g2.test"

    async with owner_session_factory() as sess, sess.begin():
        sess.add(
            Tenant(tenant_id=tenant_id, name="G2 Tenant", blast_radius_k_max=3, created_at=NOW_UTC)
        )
        await sess.flush()
        sess.add(
            User(
                user_id=user_id,
                tenant_id=tenant_id,
                email=email,
                password_hash=hash_password("StrongPass!123"),
                role=UserRole.APPROVER,
                is_active=True,
                created_at=NOW_UTC,
            )
        )

    # 1. Login and verify valid EdDSA token
    pair1 = await auth.login(email=email, password="StrongPass!123", now_utc=NOW_UTC)
    claims = decode_access_token(public_key=pub, token=pair1.access_token, now_utc=NOW_UTC)
    assert claims.role == "APPROVER"

    # 2. Demote user in PostgreSQL while JWT is still valid -> authoritative DB check rejects
    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        await sess.execute(
            update(User).where(User.user_id == user_id).values(role=UserRole.ANALYST)
        )

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        with pytest.raises(InsufficientRoleError):
            await auth.verify_authoritative_role(
                session=sess,
                user_id=user_id,
                required_role=UserRole.APPROVER,
            )

    # 3. Rotate refresh token once, then replay old token -> entire family revoked
    pair2 = await auth.refresh(raw_refresh_token=pair1.refresh_token, now_utc=NOW_UTC + 10)
    assert pair2.refresh_token != pair1.refresh_token

    with pytest.raises(RefreshTokenReuseError):
        await auth.refresh(raw_refresh_token=pair1.refresh_token, now_utc=NOW_UTC + 20)

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        tokens = (await sess.execute(select(RefreshToken))).scalars().all()
        assert len(tokens) == 2
        assert all(t.revoked_at is not None for t in tokens)
