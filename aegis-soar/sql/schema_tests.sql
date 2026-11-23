\set ON_ERROR_STOP on

BEGIN;

-- ----------------------------------------------------------------------------
-- 0. Seed Fixtures as postgres (superuser for test fixture setup)
-- ----------------------------------------------------------------------------
RESET ROLE;

INSERT INTO tenants (tenant_id, name, blast_radius_k_max, created_at) VALUES
    ('11111111-1111-1111-1111-111111111111', 'Tenant Alpha', 3, 1700000000),
    ('22222222-2222-2222-2222-222222222222', 'Tenant Beta',  3, 1700000000);

INSERT INTO users (user_id, tenant_id, email, password_hash, role, is_active, mfa_secret_enc, created_at) VALUES
    ('10000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'analyst@alpha.test',  '$argon2id$v=19$m=65536,t=3,p=4$salt$hash1', 'ANALYST',      true, E'\\xDEADBEEF', 1700000000),
    ('10000000-0000-0000-0000-000000000002', '11111111-1111-1111-1111-111111111111', 'approver@alpha.test', '$argon2id$v=19$m=65536,t=3,p=4$salt$hash2', 'APPROVER',     true, E'\\xCAFEBABE', 1700000000),
    ('10000000-0000-0000-0000-000000000003', '11111111-1111-1111-1111-111111111111', 'admin@alpha.test',    '$argon2id$v=19$m=65536,t=3,p=4$salt$hash3', 'TENANT_ADMIN', true, E'\\xFEEDFACE', 1700000000),
    ('20000000-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'analyst@beta.test',   '$argon2id$v=19$m=65536,t=3,p=4$salt$hash4', 'ANALYST',      true, E'\\xBAADF00D', 1700000000);

INSERT INTO protected_assets (asset_id, tenant_id, protected_cidr, label, created_by, created_at) VALUES
    ('aaaaaaaa-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', '10.0.0.0/24', 'Alpha Domain Controllers', '10000000-0000-0000-0000-000000000003', 1700000000);

INSERT INTO incidents (incident_id, tenant_id, idempotency_key, mitre_technique_id, severity, triage_summary_untrusted, created_at) VALUES
    ('bbbbbbbb-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'inc-alpha-1', 'T1059', 'HIGH', 'untrusted text', 1700000000),
    ('bbbbbbbb-0000-0000-0000-000000000002', '22222222-2222-2222-2222-222222222222', 'inc-beta-1',  'T1059', 'HIGH', 'untrusted text', 1700000000);

INSERT INTO audit_log (tenant_id, actor_user_id, event_type, entity_type, entity_id, payload, prev_hash, event_hash, created_at) VALUES
    ('11111111-1111-1111-1111-111111111111', '10000000-0000-0000-0000-000000000001', 'INCIDENT_CREATED', 'incident', 'bbbbbbbb-0000-0000-0000-000000000001', '{}'::jsonb, '0000', 'abcd', 1700000000);
-- ----------------------------------------------------------------------------
-- Switch to aegis_app for ALL invariant tests
-- ----------------------------------------------------------------------------
RESET ROLE;
SET LOCAL ROLE aegis_app;

-- TEST 1 (INV-1): Fail-closed RLS when app.current_tenant_id is unset
DO $$
DECLARE
    v_count int;
BEGIN
    SELECT COUNT(*) INTO v_count FROM users;
    IF v_count <> 0 THEN
        RAISE EXCEPTION 'FAIL TEST 1: Expected 0 users with unset tenant_id, got %', v_count;
    END IF;
    RAISE NOTICE 'PASS TEST 1: Fail-closed RLS with unset tenant_id';
END
$$;

-- TEST 2 (INV-1): auth_lookup_identity works pre-login and excludes mfa_secret_enc
DO $$
DECLARE
    v_rec record;
    v_has_mfa_col boolean;
BEGIN
    SELECT * INTO v_rec FROM auth_lookup_identity('approver@alpha.test');
    IF v_rec.tenant_id <> '11111111-1111-1111-1111-111111111111'::uuid THEN
        RAISE EXCEPTION 'FAIL TEST 2: Unexpected tenant_id %', v_rec.tenant_id;
    END IF;

    SELECT EXISTS (
        SELECT 1
          FROM pg_proc p
         WHERE p.proname = 'auth_lookup_identity'
           AND pg_get_function_result(p.oid) ILIKE '%mfa_secret_enc%'
    ) INTO v_has_mfa_col;

    IF v_has_mfa_col THEN
        RAISE EXCEPTION 'FAIL TEST 2: auth_lookup_identity MUST NOT expose mfa_secret_enc';
    END IF;
    RAISE NOTICE 'PASS TEST 2: auth_lookup_identity resolves identity without mfa_secret_enc';
END
$$;

-- Bind Tenant Alpha for remaining tests
SELECT set_config('app.current_tenant_id', '11111111-1111-1111-1111-111111111111', true);

-- TEST 3 (INV-1): Cross-tenant isolation (Alpha cannot see Beta)
DO $$
DECLARE
    v_count int;
BEGIN
    SELECT COUNT(*) INTO v_count
      FROM incidents
     WHERE tenant_id = '22222222-2222-2222-2222-222222222222'::uuid;
    IF v_count <> 0 THEN
        RAISE EXCEPTION 'FAIL TEST 3: Cross-tenant incident leak detected';
    END IF;
    RAISE NOTICE 'PASS TEST 3: Cross-tenant RLS isolation verified';
END
$$;

-- TEST 4 (INV-5): Reject IPv4-mapped IPv6 (::ffff:0:0/96) via CHECK constraint
DO $$
BEGIN
    INSERT INTO response_actions (
        action_id, tenant_id, incident_id, idempotency_key, action_type,
        target_ip, state, ttl_seconds, approval_expires_at, proposed_by, created_at, updated_at
    ) VALUES (
        'cccccccc-0000-0000-0000-000000000001',
        '11111111-1111-1111-1111-111111111111',
        'bbbbbbbb-0000-0000-0000-000000000001',
        'act-ipv4-mapped', 'FIREWALL_BLOCK_IP',
        '::ffff:10.0.0.5'::inet, 'PENDING_APPROVAL', 300, 1700003600,
        '10000000-0000-0000-0000-000000000001', 1700000000, 1700000000
    );
    RAISE EXCEPTION 'FAIL TEST 4: IPv4-mapped IPv6 was not rejected';
EXCEPTION
    WHEN check_violation THEN
        RAISE NOTICE 'PASS TEST 4: ::ffff:0:0/96 rejected by CHECK constraint';
END
$$;

-- TEST 5 (INV-5): Reject target_ip covered by protected_assets CIDR via trigger
DO $$
BEGIN
    INSERT INTO response_actions (
        action_id, tenant_id, incident_id, idempotency_key, action_type,
        target_ip, state, ttl_seconds, approval_expires_at, proposed_by, created_at, updated_at
    ) VALUES (
        'cccccccc-0000-0000-0000-000000000002',
        '11111111-1111-1111-1111-111111111111',
        'bbbbbbbb-0000-0000-0000-000000000001',
        'act-allowlist-hit', 'HOST_ISOLATE',
        '10.0.0.42'::inet, 'PENDING_APPROVAL', 300, 1700003600,
        '10000000-0000-0000-0000-000000000001', 1700000000, 1700000000
    );
    RAISE EXCEPTION 'FAIL TEST 5: Protected CIDR target was not rejected';
EXCEPTION
    WHEN raise_exception THEN
        IF SQLERRM NOT LIKE '%ALLOWLIST_VIOLATION%' THEN
            RAISE EXCEPTION 'FAIL TEST 5: Unexpected error %', SQLERRM;
        END IF;
        RAISE NOTICE 'PASS TEST 5: Protected CIDR rejected by trigger';
END
$$;

-- Insert a valid PENDING_APPROVAL action for Tests 6, 7, 8
INSERT INTO response_actions (
    action_id, tenant_id, incident_id, idempotency_key, action_type,
    target_ip, state, ttl_seconds, approval_expires_at, proposed_by, created_at, updated_at
) VALUES (
    'cccccccc-0000-0000-0000-000000000010',
    '11111111-1111-1111-1111-111111111111',
    'bbbbbbbb-0000-0000-0000-000000000001',
    'act-valid-1', 'FIREWALL_BLOCK_IP',
    '198.51.100.25'::inet, 'PENDING_APPROVAL', 300, 1700003600,
    '10000000-0000-0000-0000-000000000001', 1700000000, 1700000000
);

-- TEST 6 (INV-2): 4-Eyes / Approver role rejects self-approval by non-approver
DO $$
BEGIN
    UPDATE response_actions
       SET state = 'EXECUTING',
           approved_by = '10000000-0000-0000-0000-000000000001',
           mfa_verified_at = 1700000010,
           slot_reserved_at = 1700000010
     WHERE action_id = 'cccccccc-0000-0000-0000-000000000010';
    RAISE EXCEPTION 'FAIL TEST 6: Self-approval was not rejected';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS TEST 6: Self-approval rejected at DB layer';
END
$$;

-- TEST 7 (INV-2): Approver role trigger rejects non-APPROVER (TENANT_ADMIN)
DO $$
BEGIN
    UPDATE response_actions
       SET state = 'EXECUTING',
           approved_by = '10000000-0000-0000-0000-000000000003',
           mfa_verified_at = 1700000010,
           slot_reserved_at = 1700000010
     WHERE action_id = 'cccccccc-0000-0000-0000-000000000010';
    RAISE EXCEPTION 'FAIL TEST 7: Non-APPROVER role was allowed to approve';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'PASS TEST 7: Non-APPROVER rejected by enforce_approver_role trigger';
END
$$;

-- TEST 8 (§3.1): State transition trigger rejects illegal jump PENDING_APPROVAL -> EXECUTED
DO $$
BEGIN
    UPDATE response_actions
       SET state = 'EXECUTED',
           approved_by = '10000000-0000-0000-0000-000000000002',
           mfa_verified_at = 1700000010,
           expires_at = 1700000310
     WHERE action_id = 'cccccccc-0000-0000-0000-000000000010';
    RAISE EXCEPTION 'FAIL TEST 8: Illegal transition PENDING_APPROVAL -> EXECUTED succeeded';
EXCEPTION
    WHEN invalid_parameter_value THEN
        RAISE NOTICE 'PASS TEST 8: Illegal state transition rejected by trigger';
END
$$;

-- TEST 9 (INV-8): audit_log rejects UPDATE, DELETE, and TRUNCATE
DO $$
BEGIN
    BEGIN
        UPDATE audit_log SET event_type = 'TAMPERED';
        RAISE EXCEPTION 'FAIL TEST 9a: UPDATE on audit_log succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS TEST 9a: UPDATE on audit_log rejected';
    END;

    BEGIN
        DELETE FROM audit_log;
        RAISE EXCEPTION 'FAIL TEST 9b: DELETE on audit_log succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS TEST 9b: DELETE on audit_log rejected';
    END;

    BEGIN
        TRUNCATE TABLE audit_log;
        RAISE EXCEPTION 'FAIL TEST 9c: TRUNCATE on audit_log succeeded';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'PASS TEST 9c: TRUNCATE on audit_log rejected';
    END;
END
$$;

ROLLBACK;