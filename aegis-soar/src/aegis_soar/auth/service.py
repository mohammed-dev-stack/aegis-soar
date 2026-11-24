from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis_soar.audit.logger import append_audit_event
from aegis_soar.auth.crypto import (
    MAX_ACCESS_TOKEN_TTL_SECONDS,
    constant_time_equals,
    decrypt_mfa_secret,
    encode_access_token,
    generate_refresh_token,
    parse_refresh_token_tenant,
    sha256_hex,
    verify_dummy_password,
    verify_password,
    verify_totp_code,
)
from aegis_soar.db.models import RefreshToken, User, UserRole
from aegis_soar.tenancy.context import pre_auth_session, tenant_transaction

MFA_MAX_FAILED_ATTEMPTS = 5
MFA_LOCKOUT_SECONDS = 900
REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 3600


class AuthError(Exception):
    """Base authentication/authorization error."""

    status_code: int = 401
    error_code: str = "UNAUTHORIZED"


class InvalidCredentialsError(AuthError):
    status_code = 401
    error_code = "INVALID_CREDENTIALS"


class AccountDisabledError(AuthError):
    status_code = 403
    error_code = "ACCOUNT_DISABLED"


class InvalidTokenError(AuthError):
    status_code = 401
    error_code = "REFRESH_TOKEN_INVALID"


class RefreshTokenReuseError(AuthError):
    status_code = 401
    error_code = "REFRESH_TOKEN_REUSE_DETECTED"


class InsufficientRoleError(AuthError):
    status_code = 403
    error_code = "INSUFFICIENT_ROLE"


class MfaLockedError(AuthError):
    status_code = 423
    error_code = "MFA_LOCKED"


class InvalidTotpError(AuthError):
    status_code = 401
    error_code = "TOTP_INVALID"


class TotpReplayError(AuthError):
    status_code = 409
    error_code = "TOTP_REPLAY_DETECTED"


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    user_id: UUID
    tenant_id: UUID
    role: UserRole


class AuthService:
    """Authentication, token rotation, authoritative RBAC, and TOTP MFA service."""

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        jwt_private_key: Ed25519PrivateKey,
        jwt_public_key: Ed25519PublicKey,
        mfa_kek: bytes,
    ) -> None:
        self._session_factory = session_factory
        self._jwt_private_key = jwt_private_key
        self._jwt_public_key = jwt_public_key
        self._mfa_kek = mfa_kek

    async def login(self, *, email: str, password: str, now_utc: int) -> TokenPair:
        """Authenticate via auth_lookup_identity (SECURITY DEFINER) and issue EdDSA + refresh."""
        normalized_email = email.strip().lower()
        async with pre_auth_session(self._session_factory) as session:
            row = (
                await session.execute(
                    text("SELECT * FROM public.auth_lookup_identity(:p_email)"),
                    {"p_email": normalized_email},
                )
            ).one_or_none()

        if row is None:
            verify_dummy_password(password)
            raise InvalidCredentialsError("Invalid email or password")

        if not verify_password(str(row.password_hash), password):
            raise InvalidCredentialsError("Invalid email or password")

        if not bool(row.is_active):
            raise AccountDisabledError("Account is disabled")

        user_id = UUID(str(row.user_id))
        tenant_id = UUID(str(row.tenant_id))
        role = UserRole(str(row.role))

        access_token = encode_access_token(
            private_key=self._jwt_private_key,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role.value,
            now_utc=now_utc,
            ttl_seconds=MAX_ACCESS_TOKEN_TTL_SECONDS,
        )
        raw_refresh, token_hash = generate_refresh_token(tenant_id)
        family_id = uuid4()

        async with tenant_transaction(self._session_factory, tenant_id) as session:
            session.add(
                RefreshToken(
                    token_id=uuid4(),
                    tenant_id=tenant_id,
                    user_id=user_id,
                    family_id=family_id,
                    token_hash=token_hash,
                    expires_at=now_utc + REFRESH_TOKEN_TTL_SECONDS,
                    revoked_at=None,
                    created_at=now_utc,
                )
            )
            await append_audit_event(
                session=session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                event_type="AUTH_LOGIN_SUCCESS",
                entity_type="user",
                entity_id=user_id,
                payload={"family_id": str(family_id)},
                now_utc=now_utc,
            )

        return TokenPair(
            access_token=access_token,
            refresh_token=raw_refresh,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
        )

    async def refresh(self, *, raw_refresh_token: str, now_utc: int) -> TokenPair:
        """Rotate a refresh token under RLS; revoke entire token family on reuse."""
        try:
            tenant_id = parse_refresh_token_tenant(raw_refresh_token)
        except ValueError as exc:
            raise InvalidTokenError("Malformed refresh token") from exc

        presented_hash = sha256_hex(raw_refresh_token)
        reuse_detected = False

        async with tenant_transaction(self._session_factory, tenant_id) as session:
            token_row = (
                await session.execute(
                    select(RefreshToken)
                    .where(RefreshToken.token_hash == presented_hash)
                    .with_for_update()
                )
            ).scalar_one_or_none()

            if token_row is None or not constant_time_equals(token_row.token_hash, presented_hash):
                raise InvalidTokenError("Refresh token not found")

            if token_row.revoked_at is not None:
                # Reuse detected: revoke entire family and commit audit event before raising.
                await session.execute(
                    update(RefreshToken)
                    .where(
                        RefreshToken.family_id == token_row.family_id,
                        RefreshToken.revoked_at.is_(None),
                    )
                    .values(revoked_at=now_utc)
                )
                await append_audit_event(
                    session=session,
                    tenant_id=tenant_id,
                    actor_user_id=token_row.user_id,
                    event_type="SECURITY_TOKEN_REUSE",
                    entity_type="refresh_token_family",
                    entity_id=token_row.family_id,
                    payload={"reused_token_id": str(token_row.token_id)},
                    now_utc=now_utc,
                )
                reuse_detected = True
            else:
                if token_row.expires_at <= now_utc:
                    raise InvalidTokenError("Refresh token expired")

                user = (
                    await session.execute(select(User).where(User.user_id == token_row.user_id))
                ).scalar_one_or_none()
                if user is None or not user.is_active:
                    raise AccountDisabledError("Account is disabled")

                token_row.revoked_at = now_utc
                new_raw_refresh, new_hash = generate_refresh_token(tenant_id)
                session.add(
                    RefreshToken(
                        token_id=uuid4(),
                        tenant_id=tenant_id,
                        user_id=user.user_id,
                        family_id=token_row.family_id,
                        token_hash=new_hash,
                        expires_at=now_utc + REFRESH_TOKEN_TTL_SECONDS,
                        revoked_at=None,
                        created_at=now_utc,
                    )
                )
                new_access = encode_access_token(
                    private_key=self._jwt_private_key,
                    user_id=user.user_id,
                    tenant_id=tenant_id,
                    role=user.role.value,
                    now_utc=now_utc,
                    ttl_seconds=MAX_ACCESS_TOKEN_TTL_SECONDS,
                )
                pair = TokenPair(
                    access_token=new_access,
                    refresh_token=new_raw_refresh,
                    user_id=user.user_id,
                    tenant_id=tenant_id,
                    role=user.role,
                )

        if reuse_detected:
            raise RefreshTokenReuseError("Refresh token reuse detected; token family revoked")

        return pair

    async def verify_authoritative_role(
        self,
        *,
        session: AsyncSession,
        user_id: UUID,
        required_role: UserRole,
    ) -> User:
        """Re-read users.role and is_active from PostgreSQL inside the active transaction."""
        user = (
            await session.execute(select(User).where(User.user_id == user_id))
        ).scalar_one_or_none()
        if user is None or not user.is_active or user.role != required_role:
            raise InsufficientRoleError(f"Active database role {required_role.value} is required")
        return user

    async def _record_totp_failure_autonomous(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        now_utc: int,
    ) -> None:
        """Commit failed TOTP attempt + 15-minute lockout in an independent transaction (INV-3)."""
        async with tenant_transaction(self._session_factory, tenant_id) as iso_session:
            row = (
                await iso_session.execute(
                    text(
                        """
                        UPDATE users
                        SET mfa_failed_attempts = mfa_failed_attempts + 1,
                            mfa_locked_until = CASE
                                WHEN mfa_failed_attempts + 1 >= :max_attempts
                                THEN :lock_until
                                ELSE mfa_locked_until
                            END
                        WHERE user_id = :u
                        RETURNING mfa_failed_attempts, mfa_locked_until
                        """
                    ),
                    {
                        "max_attempts": MFA_MAX_FAILED_ATTEMPTS,
                        "lock_until": now_utc + MFA_LOCKOUT_SECONDS,
                        "u": user_id,
                    },
                )
            ).one_or_none()
            if row is not None:
                await append_audit_event(
                    session=iso_session,
                    tenant_id=tenant_id,
                    actor_user_id=user_id,
                    event_type="AUTH_TOTP_FAILURE",
                    entity_type="user",
                    entity_id=user_id,
                    payload={
                        "mfa_failed_attempts": int(row.mfa_failed_attempts),
                        "mfa_locked_until": row.mfa_locked_until,
                    },
                    now_utc=now_utc,
                )

    async def verify_and_consume_totp(
        self,
        *,
        session: AsyncSession,
        tenant_id: UUID,
        user: User,
        totp_code: str | None,
        now_utc: int,
    ) -> int:
        """Verify per-action TOTP code with atomic replay protection and autonomous lockout."""
        if user.mfa_locked_until is not None and user.mfa_locked_until > now_utc:
            raise MfaLockedError("MFA is temporarily locked due to repeated failures")

        if not totp_code or user.mfa_secret_enc is None:
            await self._record_totp_failure_autonomous(
                tenant_id=tenant_id,
                user_id=user.user_id,
                now_utc=now_utc,
            )
            raise InvalidTotpError("Missing or invalid TOTP code")

        base32_secret = decrypt_mfa_secret(
            kek=self._mfa_kek,
            user_id=user.user_id,
            tenant_id=tenant_id,
            encrypted_blob=user.mfa_secret_enc,
        )
        matched_step = verify_totp_code(base32_secret, totp_code, now_utc)
        if matched_step is None:
            await self._record_totp_failure_autonomous(
                tenant_id=tenant_id,
                user_id=user.user_id,
                now_utc=now_utc,
            )
            raise InvalidTotpError("Invalid TOTP code")

        claimed = (
            await session.execute(
                text(
                    """
                    UPDATE users
                    SET last_used_totp_step = :step,
                        mfa_failed_attempts = 0,
                        mfa_locked_until = NULL
                    WHERE user_id = :u
                      AND last_used_totp_step < :step
                    RETURNING user_id
                    """
                ),
                {"step": matched_step, "u": user.user_id},
            )
        ).one_or_none()

        if claimed is None:
            raise TotpReplayError("TOTP code step already consumed")

        return matched_step
