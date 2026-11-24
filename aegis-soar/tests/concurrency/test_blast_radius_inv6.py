from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pyotp
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
    BlastRadiusExceededError,
    LockStrategy,
    NoopLock,
    PgAdvisoryBlastLock,
    ResponseService,
)
from aegis_soar.tenancy.context import tenant_transaction

NOW_UTC = 1700040000
CONCURRENCY = 10
K_MAX = 3


async def _run_blast_radius_race(
    *,
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
    lock_strategy: LockStrategy,
) -> tuple[list[ResponseAction], list[BlastRadiusExceededError], UUID]:
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
        lock_strategy=lock_strategy,
    )

    tenant_id = uuid4()
    analyst_id = uuid4()
    incident_id = uuid4()
    approvers: list[tuple[UUID, str]] = [
        (uuid4(), generate_totp_base32_secret()) for _ in range(CONCURRENCY)
    ]
    action_ids: list[UUID] = [uuid4() for _ in range(CONCURRENCY)]

    async with owner_session_factory() as sess, sess.begin():
        sess.add(
            Tenant(
                tenant_id=tenant_id, name="G3 Blast", blast_radius_k_max=K_MAX, created_at=NOW_UTC
            )
        )
        await sess.flush()
        sess.add(
            User(
                user_id=analyst_id,
                tenant_id=tenant_id,
                email=f"analyst-{analyst_id}@blast.test",
                password_hash=hash_password("Pass!123"),
                role=UserRole.ANALYST,
                created_at=NOW_UTC,
            )
        )
        for uid, secret in approvers:
            sess.add(
                User(
                    user_id=uid,
                    tenant_id=tenant_id,
                    email=f"approver-{uid}@blast.test",
                    password_hash=hash_password("Pass!123"),
                    role=UserRole.APPROVER,
                    mfa_secret_enc=encrypt_mfa_secret(
                        kek=kek, user_id=uid, tenant_id=tenant_id, base32_secret=secret
                    ),
                    created_at=NOW_UTC,
                )
            )
        sess.add(
            Incident(
                incident_id=incident_id,
                tenant_id=tenant_id,
                idempotency_key=f"inc-{incident_id}",
                mitre_technique_id="T1110",
                severity="HIGH",
                created_at=NOW_UTC,
            )
        )
        await sess.flush()
        for idx, aid in enumerate(action_ids):
            atype = ActionType.HOST_ISOLATE if idx % 2 == 0 else ActionType.FIREWALL_BLOCK_IP
            sess.add(
                ResponseAction(
                    action_id=aid,
                    tenant_id=tenant_id,
                    incident_id=incident_id,
                    idempotency_key=f"blast-{aid}",
                    action_type=atype,
                    target_ip=f"203.0.113.{idx + 10}",
                    state=ActionState.PENDING_APPROVAL,
                    ttl_seconds=600,
                    approval_expires_at=NOW_UTC + 3600,
                    proposed_by=analyst_id,
                    created_at=NOW_UTC,
                    updated_at=NOW_UTC,
                )
            )

    barrier = asyncio.Barrier(CONCURRENCY)

    async def _worker(idx: int) -> ResponseAction | BaseException:
        uid, secret = approvers[idx]
        code = pyotp.TOTP(secret).at(NOW_UTC)
        await barrier.wait()
        try:
            return await svc.approve_and_execute_action(
                tenant_id=tenant_id,
                action_id=action_ids[idx],
                approver_user_id=uid,
                totp_code=code,
                now_utc=NOW_UTC,
            )
        except BaseException as exc:
            return exc

    results = await asyncio.gather(*(_worker(i) for i in range(CONCURRENCY)))
    executed = [r for r in results if isinstance(r, ResponseAction)]
    rejected = [r for r in results if isinstance(r, BlastRadiusExceededError)]
    return executed, rejected, tenant_id


async def test_g3_blast_radius_cap_strictly_enforced_under_10x_concurrency(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G3 (INV-6): 10 simultaneous approvers vs K_max=3 -> exactly 3 EXECUTED, 7 HTTP 429."""
    executed, rejected, tenant_id = await _run_blast_radius_race(
        app_session_factory=app_session_factory,
        owner_session_factory=owner_session_factory,
        lock_strategy=PgAdvisoryBlastLock(),
    )
    assert len(executed) == K_MAX
    assert len(rejected) == CONCURRENCY - K_MAX

    async with tenant_transaction(app_session_factory, tenant_id) as sess:
        rows = (await sess.execute(select(ResponseAction))).scalars().all()
        assert sum(1 for r in rows if r.state == ActionState.EXECUTED) == K_MAX
        assert (
            sum(1 for r in rows if r.state == ActionState.PENDING_APPROVAL) == CONCURRENCY - K_MAX
        )


async def test_g3_negative_race_proof_without_advisory_lock_breaches_cap(
    app_session_factory: async_sessionmaker[AsyncSession],
    owner_session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Gate G3 Negative Proof: removing pg_advisory_xact_lock MUST breach K_max=3 under race."""
    executed, _, _ = await _run_blast_radius_race(
        app_session_factory=app_session_factory,
        owner_session_factory=owner_session_factory,
        lock_strategy=NoopLock(),
    )
    assert len(executed) > K_MAX, "Negative race-proof failed: NoopLock did not breach K_max!"
