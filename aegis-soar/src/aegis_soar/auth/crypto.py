from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_ACCESS_TOKEN_TTL_SECONDS = 900
TOTP_STEP_SECONDS = 30
TOTP_DRIFT_STEPS = 1

_ARGON2_HASHER = PasswordHasher(
    memory_cost=65536,
    time_cost=3,
    parallelism=4,
)
_DUMMY_PASSWORD_HASH: str = _ARGON2_HASHER.hash("aegis-soar-dummy-timing-guard-password")


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    sub: UUID
    tid: UUID
    role: str
    jti: UUID
    iat: int
    exp: int


def hash_password(plain_password: str) -> str:
    """Hash a password using Argon2id (64 MiB, t=3, p=4)."""
    return _ARGON2_HASHER.hash(plain_password)


def verify_password(password_hash: str, plain_password: str) -> bool:
    """Verify an Argon2id password hash; rejects legacy hash formats."""
    if not password_hash.startswith("$argon2id$"):
        return False
    try:
        return _ARGON2_HASHER.verify(password_hash, plain_password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def verify_dummy_password(plain_password: str) -> None:
    """Execute a constant-cost Argon2id check for unknown emails to mitigate timing enumeration."""
    with contextlib.suppress(VerifyMismatchError, InvalidHashError):
        _ARGON2_HASHER.verify(_DUMMY_PASSWORD_HASH, plain_password)


def sha256_hex(raw_value: str) -> str:
    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def generate_refresh_token(tenant_id: UUID) -> tuple[str, str]:
    """Generate an opaque refresh token prefixed with tenant_id and its SHA-256 hex digest."""
    random_part = secrets.token_urlsafe(32)
    raw_token = f"{tenant_id}.{random_part}"
    return raw_token, sha256_hex(raw_token)


def parse_refresh_token_tenant(raw_token: str) -> UUID:
    """Extract the tenant_id UUID prefix from '<tenant_id_uuid>.<secret>'."""
    parts = raw_token.split(".", 1)
    if len(parts) != 2 or not parts[1]:
        raise ValueError("Malformed refresh token")
    return UUID(parts[0])


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def encode_access_token(
    *,
    private_key: Ed25519PrivateKey,
    user_id: UUID,
    tenant_id: UUID,
    role: str,
    now_utc: int,
    ttl_seconds: int = MAX_ACCESS_TOKEN_TTL_SECONDS,
) -> str:
    """Mint an EdDSA (Ed25519) JWT access token with mandatory jti, sub, tid, iat, exp."""
    if ttl_seconds <= 0 or ttl_seconds > MAX_ACCESS_TOKEN_TTL_SECONDS:
        raise ValueError(f"Access token TTL must be in (0, {MAX_ACCESS_TOKEN_TTL_SECONDS}]")
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "tid": str(tenant_id),
        "role": role,
        "jti": str(uuid4()),
        "iat": now_utc,
        "exp": now_utc + ttl_seconds,
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA")


def decode_access_token(
    *,
    public_key: Ed25519PublicKey,
    token: str,
    now_utc: int | None = None,
) -> AccessTokenClaims:
    """Verify an EdDSA JWT access token; explicitly rejects alg=none, HS256, and RS256."""
    header = jwt.get_unverified_header(token)
    if header.get("alg") != "EdDSA":
        raise jwt.InvalidAlgorithmError(f"Forbidden JWT algorithm: {header.get('alg')!r}")

    decoded: dict[str, Any] = jwt.decode(
        token,
        public_key,
        algorithms=["EdDSA"],
        options={
            "require": ["jti", "sub", "tid", "iat", "exp"],
            "verify_signature": True,
            "verify_exp": now_utc is None,
        },
    )
    exp = int(decoded["exp"])
    iat = int(decoded["iat"])
    if now_utc is not None and exp <= now_utc:
        raise jwt.ExpiredSignatureError("Token expired")
    if exp - iat > MAX_ACCESS_TOKEN_TTL_SECONDS:
        raise jwt.InvalidTokenError("Token TTL exceeds maximum allowed window")

    return AccessTokenClaims(
        sub=UUID(str(decoded["sub"])),
        tid=UUID(str(decoded["tid"])),
        role=str(decoded.get("role", "")),
        jti=UUID(str(decoded["jti"])),
        iat=iat,
        exp=exp,
    )


def _mfa_aad(user_id: UUID, tenant_id: UUID) -> bytes:
    return f"{user_id}:{tenant_id}".encode()


def generate_mfa_kek() -> bytes:
    """Generate a 256-bit AES-GCM envelope key (KEK) for TOTP secret encryption."""
    return os.urandom(32)


def encrypt_mfa_secret(
    *,
    kek: bytes,
    user_id: UUID,
    tenant_id: UUID,
    base32_secret: str,
) -> bytes:
    """Encrypt a TOTP base32 seed using AES-256-GCM with a 96-bit nonce and bound AAD."""
    if len(kek) != 32:
        raise ValueError("AEGIS_MFA_KEK must be exactly 32 bytes (256 bits)")
    nonce = os.urandom(12)
    ciphertext = AESGCM(kek).encrypt(
        nonce,
        base32_secret.encode("ascii"),
        _mfa_aad(user_id, tenant_id),
    )
    return nonce + ciphertext


def decrypt_mfa_secret(
    *,
    kek: bytes,
    user_id: UUID,
    tenant_id: UUID,
    encrypted_blob: bytes,
) -> str:
    """Decrypt an AES-256-GCM encrypted TOTP base32 seed."""
    if len(kek) != 32 or len(encrypted_blob) < 28:
        raise ValueError("Invalid MFA KEK or ciphertext")
    nonce = encrypted_blob[:12]
    ciphertext = encrypted_blob[12:]
    plaintext = AESGCM(kek).decrypt(
        nonce,
        ciphertext,
        _mfa_aad(user_id, tenant_id),
    )
    return plaintext.decode("ascii")


def verify_totp_code(base32_secret: str, code: str, now_utc: int) -> int | None:
    """Verify a 6-digit RFC 6238 TOTP code within +/- 1 step using constant-time comparison.

    Returns the matched integer time step on success, or None on mismatch.
    """
    if len(code) != 6 or not code.isdigit():
        return None
    totp = pyotp.TOTP(base32_secret, interval=TOTP_STEP_SECONDS)
    current_step = now_utc // TOTP_STEP_SECONDS
    for delta in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
        candidate_step = current_step + delta
        if candidate_step <= 0:
            continue
        expected = totp.at(candidate_step * TOTP_STEP_SECONDS)
        if constant_time_equals(code, expected):
            return candidate_step
    return None


def generate_totp_base32_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii")
