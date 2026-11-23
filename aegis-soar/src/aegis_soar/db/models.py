from __future__ import annotations

import enum
import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class UserRole(enum.StrEnum):
    TENANT_ADMIN = "TENANT_ADMIN"
    ANALYST = "ANALYST"
    APPROVER = "APPROVER"
    AUDITOR = "AUDITOR"


class ActionType(enum.StrEnum):
    HOST_ISOLATE = "HOST_ISOLATE"
    FIREWALL_BLOCK_IP = "FIREWALL_BLOCK_IP"


class ActionState(enum.StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class Base(DeclarativeBase):
    """Declarative base for Aegis-SOAR ORM models."""


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("blast_radius_k_max > 0", name="tenants_blast_radius_k_max_check"),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    blast_radius_k_max: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("last_used_totp_step >= 0", name="users_last_used_totp_step_check"),
        CheckConstraint("mfa_failed_attempts >= 0", name="users_mfa_failed_attempts_check"),
        Index("idx_users_tenant_id", "tenant_id"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", create_type=False),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    last_used_totp_step: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    mfa_failed_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mfa_locked_until: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (Index("idx_refresh_tokens_tenant_family", "tenant_id", "family_id"),)

    token_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class ProtectedAsset(Base):
    __tablename__ = "protected_assets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "protected_cidr",
            name="protected_assets_tenant_id_protected_cidr_key",
        ),
        Index("idx_protected_assets_tenant_cidr", "tenant_id", "protected_cidr"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    protected_cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    label: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (Index("idx_events_tenant_occurred", "tenant_id", "occurred_at"),)

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    occurred_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    ingested_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="incidents_tenant_id_idempotency_key_key",
        ),
        Index("idx_incidents_tenant_created", "tenant_id", "created_at"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_technique_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    triage_summary_untrusted: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="response_actions_tenant_id_idempotency_key_key",
        ),
        CheckConstraint(
            "NOT (target_ip <<= '::ffff:0:0/96'::cidr)",
            name="response_actions_target_ip_check",
        ),
        CheckConstraint("ttl_seconds > 0", name="response_actions_ttl_seconds_check"),
        CheckConstraint(
            "approved_by IS NULL OR approved_by <> proposed_by",
            name="chk_four_eyes",
        ),
        CheckConstraint(
            "state IN ('PENDING_APPROVAL', 'REJECTED', 'EXPIRED') "
            "OR (approved_by IS NOT NULL AND mfa_verified_at IS NOT NULL)",
            name="chk_approval_required_for_post_pending_states",
        ),
        Index("idx_response_actions_blast_radius", "tenant_id", "state", "expires_at"),
    )

    action_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    action_type: Mapped[ActionType] = mapped_column(
        Enum(ActionType, name="action_type", create_type=False),
        nullable=False,
    )
    target_ip: Mapped[str] = mapped_column(INET, nullable=False)
    state: Mapped[ActionState] = mapped_column(
        Enum(ActionState, name="action_state", create_type=False),
        nullable=False,
        default=ActionState.PENDING_APPROVAL,
    )
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    approval_expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    slot_reserved_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    expires_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    adapter_state_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    proposed_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=False,
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=True,
    )
    mfa_verified_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("idx_audit_log_tenant_seq", "tenant_id", "audit_id"),)

    audit_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="RESTRICT"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prev_hash: Mapped[str] = mapped_column(Text, nullable=False)
    event_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
