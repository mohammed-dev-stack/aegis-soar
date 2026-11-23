BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_owner') THEN
        CREATE ROLE aegis_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
        CREATE ROLE aegis_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_auth') THEN
        CREATE ROLE aegis_auth NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_auditor') THEN
        CREATE ROLE aegis_auditor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO aegis_owner;
GRANT USAGE, CREATE ON SCHEMA public TO aegis_app, aegis_auth, aegis_auditor;

SET LOCAL ROLE aegis_owner;

CREATE TYPE user_role AS ENUM ('TENANT_ADMIN', 'ANALYST', 'APPROVER', 'AUDITOR');
CREATE TYPE action_type AS ENUM ('HOST_ISOLATE', 'FIREWALL_BLOCK_IP');
CREATE TYPE action_state AS ENUM (
    'PENDING_APPROVAL', 'APPROVED', 'EXECUTING', 'EXECUTED',
    'FAILED', 'ROLLING_BACK', 'ROLLED_BACK', 'REJECTED', 'EXPIRED'
);

CREATE TABLE tenants (
    tenant_id          uuid PRIMARY KEY,
    name               text NOT NULL,
    blast_radius_k_max int  NOT NULL DEFAULT 5 CHECK (blast_radius_k_max > 0),
    created_at         bigint NOT NULL
);

CREATE TABLE users (
    user_id             uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    email               text NOT NULL UNIQUE,
    password_hash       text NOT NULL,
    role                user_role NOT NULL,
    is_active           boolean NOT NULL DEFAULT true,
    mfa_secret_enc      bytea,
    last_used_totp_step bigint NOT NULL DEFAULT 0 CHECK (last_used_totp_step >= 0),
    mfa_failed_attempts int NOT NULL DEFAULT 0 CHECK (mfa_failed_attempts >= 0),
    mfa_locked_until    bigint,
    created_at          bigint NOT NULL
);

CREATE TABLE refresh_tokens (
    token_id    uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    user_id     uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    family_id   uuid NOT NULL,
    token_hash  text NOT NULL UNIQUE,
    expires_at  bigint NOT NULL,
    revoked_at  bigint,
    created_at  bigint NOT NULL
);

CREATE TABLE protected_assets (
    asset_id       uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    protected_cidr cidr NOT NULL,
    label          text NOT NULL,
    created_by     uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at     bigint NOT NULL,
    UNIQUE (tenant_id, protected_cidr)
);

CREATE TABLE events (
    event_id    uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    occurred_at bigint NOT NULL,
    payload     jsonb NOT NULL,
    ingested_at bigint NOT NULL
);

CREATE TABLE incidents (
    incident_id              uuid PRIMARY KEY,
    tenant_id                uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    idempotency_key          text NOT NULL,
    mitre_technique_id       text,
    severity                 text NOT NULL,
    triage_summary_untrusted text,
    created_at               bigint NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE response_actions (
    action_id           uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    incident_id         uuid NOT NULL REFERENCES incidents(incident_id) ON DELETE RESTRICT,
    idempotency_key     text NOT NULL,
    action_type         action_type NOT NULL,
    target_ip           inet NOT NULL CHECK (NOT (target_ip <<= '::ffff:0:0/96'::cidr)),
    state               action_state NOT NULL DEFAULT 'PENDING_APPROVAL',
    ttl_seconds         int NOT NULL CHECK (ttl_seconds > 0),
    approval_expires_at bigint NOT NULL,
    slot_reserved_at    bigint,
    expires_at          bigint,
    adapter_state_ref   text,
    proposed_by         uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    approved_by         uuid REFERENCES users(user_id) ON DELETE RESTRICT,
    mfa_verified_at     bigint,
    created_at          bigint NOT NULL,
    updated_at          bigint NOT NULL,
    UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT chk_four_eyes
        CHECK (approved_by IS NULL OR approved_by <> proposed_by),
    CONSTRAINT chk_approval_required_for_post_pending_states
        CHECK (
            state IN ('PENDING_APPROVAL', 'REJECTED', 'EXPIRED')
            OR (approved_by IS NOT NULL AND mfa_verified_at IS NOT NULL)
        )
);

CREATE TABLE audit_log (
    audit_id      bigserial PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants(tenant_id) ON DELETE RESTRICT,
    actor_user_id uuid REFERENCES users(user_id) ON DELETE RESTRICT,
    event_type    text NOT NULL,
    entity_type   text NOT NULL,
    entity_id     uuid,
    payload       jsonb NOT NULL,
    prev_hash     text NOT NULL,
    event_hash    text NOT NULL,
    created_at    bigint NOT NULL
);

CREATE INDEX idx_users_tenant_id ON users (tenant_id);
CREATE INDEX idx_refresh_tokens_tenant_family ON refresh_tokens (tenant_id, family_id);
CREATE INDEX idx_protected_assets_tenant_cidr ON protected_assets (tenant_id, protected_cidr);
CREATE INDEX idx_events_tenant_occurred ON events (tenant_id, occurred_at DESC);
CREATE INDEX idx_incidents_tenant_created ON incidents (tenant_id, created_at DESC);
CREATE INDEX idx_response_actions_blast_radius ON response_actions (tenant_id, state, expires_at);
CREATE INDEX idx_audit_log_tenant_seq ON audit_log (tenant_id, audit_id);

CREATE OR REPLACE FUNCTION enforce_action_state_transition()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;

    IF (OLD.state = 'PENDING_APPROVAL' AND NEW.state IN ('APPROVED', 'EXECUTING', 'REJECTED', 'EXPIRED'))
       OR (OLD.state = 'APPROVED'      AND NEW.state IN ('EXECUTING', 'EXPIRED'))
       OR (OLD.state = 'EXECUTING'     AND NEW.state IN ('EXECUTED', 'FAILED'))
       OR (OLD.state = 'EXECUTED'      AND NEW.state IN ('ROLLING_BACK'))
       OR (OLD.state = 'ROLLING_BACK'  AND NEW.state IN ('ROLLED_BACK', 'FAILED'))
    THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'INVALID_STATE_TRANSITION: % -> %', OLD.state, NEW.state
        USING ERRCODE = '22023';
END;
$$;

CREATE TRIGGER trg_enforce_action_state_transition
    BEFORE UPDATE ON response_actions
    FOR EACH ROW
    EXECUTE FUNCTION enforce_action_state_transition();

CREATE OR REPLACE FUNCTION enforce_approver_role()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_role      user_role;
    v_is_active boolean;
BEGIN
    IF NEW.approved_by IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT role, is_active
      INTO v_role, v_is_active
      FROM users
     WHERE user_id = NEW.approved_by
       AND tenant_id = NEW.tenant_id;

    IF NOT FOUND OR v_is_active IS NOT TRUE OR v_role <> 'APPROVER' THEN
        RAISE EXCEPTION 'INSUFFICIENT_ROLE: approved_by must be an active APPROVER in the same tenant'
            USING ERRCODE = '42501';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_approver_role
    BEFORE INSERT OR UPDATE ON response_actions
    FOR EACH ROW
    EXECUTE FUNCTION enforce_approver_role();

CREATE OR REPLACE FUNCTION enforce_protected_asset_allowlist()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM protected_assets
         WHERE tenant_id = NEW.tenant_id
           AND NEW.target_ip <<= protected_cidr
    ) THEN
        RAISE EXCEPTION 'ALLOWLIST_VIOLATION: target_ip % is protected', NEW.target_ip
            USING ERRCODE = 'P0001';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_protected_asset_allowlist
    BEFORE INSERT OR UPDATE ON response_actions
    FOR EACH ROW
    EXECUTE FUNCTION enforce_protected_asset_allowlist();

CREATE OR REPLACE FUNCTION audit_log_immutable_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_LOG_IMMUTABLE: % on audit_log is forbidden', TG_OP
        USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION audit_log_immutable_truncate()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_LOG_IMMUTABLE: TRUNCATE on audit_log is forbidden'
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER trg_audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_immutable_row();

CREATE TRIGGER trg_audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT
    EXECUTE FUNCTION audit_log_immutable_truncate();

ALTER TABLE users            ENABLE ROW LEVEL SECURITY;
ALTER TABLE users            FORCE  ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens   ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens   FORCE  ROW LEVEL SECURITY;
ALTER TABLE protected_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE protected_assets FORCE  ROW LEVEL SECURITY;
ALTER TABLE events           ENABLE ROW LEVEL SECURITY;
ALTER TABLE events           FORCE  ROW LEVEL SECURITY;
ALTER TABLE incidents        ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents        FORCE  ROW LEVEL SECURITY;
ALTER TABLE response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_actions FORCE  ROW LEVEL SECURITY;
ALTER TABLE audit_log        ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log        FORCE  ROW LEVEL SECURITY;

CREATE POLICY p_users_tenant_isolation ON users
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY p_refresh_tokens_tenant_isolation ON refresh_tokens
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY p_protected_assets_tenant_isolation ON protected_assets
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY p_events_tenant_isolation ON events
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY p_incidents_tenant_isolation ON incidents
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY p_response_actions_tenant_isolation ON response_actions
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY p_audit_log_tenant_isolation ON audit_log
    FOR ALL TO aegis_app
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE POLICY users_auth_lookup_policy ON users
    FOR SELECT TO aegis_auth
    USING (true);

CREATE POLICY p_audit_log_auditor_read ON audit_log
    FOR SELECT TO aegis_auditor
    USING (true);

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

GRANT SELECT ON tenants TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON users TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON refresh_tokens TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON protected_assets TO aegis_app;
GRANT SELECT, INSERT ON events TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON incidents TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON response_actions TO aegis_app;
GRANT SELECT, INSERT ON audit_log TO aegis_app;
GRANT USAGE, SELECT ON SEQUENCE audit_log_audit_id_seq TO aegis_app;

REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM aegis_app, PUBLIC;

GRANT SELECT ON users TO aegis_auth;
GRANT SELECT ON tenants, audit_log TO aegis_auditor;

RESET ROLE;
SET LOCAL ROLE aegis_auth;

CREATE OR REPLACE FUNCTION public.auth_lookup_identity(p_email text)
RETURNS TABLE (
    user_id             uuid,
    tenant_id           uuid,
    password_hash       text,
    role                user_role,
    is_active           boolean,
    mfa_failed_attempts int,
    mfa_locked_until    bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT
        u.user_id,
        u.tenant_id,
        u.password_hash,
        u.role,
        u.is_active,
        u.mfa_failed_attempts,
        u.mfa_locked_until
    FROM public.users AS u
    WHERE u.email = p_email;
$$;

REVOKE EXECUTE ON FUNCTION public.auth_lookup_identity(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.auth_lookup_identity(text) TO aegis_app;

RESET ROLE;

COMMIT;
