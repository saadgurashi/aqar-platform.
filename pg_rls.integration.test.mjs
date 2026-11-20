/**
 * Real PostgreSQL 16 Integration & RLS Security Gate Test Suite — منصة عقار 2.0
 *
 * Executes ONLY against a temporary test PostgreSQL 16 database (NEVER production).
 * Env vars required:
 *   DATABASE_URL     = Owner connection URL (used to apply 0001 -> 0002 -> 0003 & seed test fixtures)
 *   APP_DATABASE_URL = Non-privileged `aqar_app_login` URL (NOBYPASSRLS; used for ALL app & isolation tests)
 *   REQUIRE_PG_INTEGRATION = 'true' in CI (fails hard if DB env is missing)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import { PgAuthRepository } from '../../src/modules/identity/pg-auth.repository.mjs';
import { AuthSessionService } from '../../src/modules/identity/auth-session.service.mjs';
import { TestOtpProvider } from '../../src/modules/identity/otp-provider.mjs';
import { PgRateLimitStore } from '../../src/shared/auth/rate-limiter.mjs';
import { PrivateStorageService, generateOpaqueStorageKey } from '../../src/shared/storage/private-storage.service.mjs';
import { createPackageAApiHandlers } from '../../src/app/api/v1/handlers.mjs';
import { createStorageApiHandlers } from '../../src/app/api/v1/storage.handlers.mjs';
import { withTenantTransaction } from '../../src/shared/db/tenant-context.mjs';
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME } from '../../src/shared/auth/cookies.mjs';

const DATABASE_URL = process.env.DATABASE_URL;
const APP_DATABASE_URL = process.env.APP_DATABASE_URL;
const REQUIRE_PG = process.env.REQUIRE_PG_INTEGRATION === 'true';

const PEPPER = 'aqar-2.0-pg-integration-test-pepper-32chars!';
const SIGNING_SECRET = 'aqar-2.0-pg-storage-signing-secret-32chars!';
const ORIGIN = 'https://aqar.sd';

const ORG_A = '11111111-1111-1111-1111-111111111111';
const ORG_B = '22222222-2222-2222-2222-222222222222';
const USER_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const USER_B = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const MEM_A = 'aaaa1111-1111-1111-1111-111111111111';
const MEM_B = 'bbbb2222-2222-2222-2222-222222222222';
const PROP_A = '33333333-3333-3333-3333-333333333331';
const PROP_B = '33333333-3333-3333-3333-333333333332';
const DOC_A = '55555555-5555-5555-5555-555555555551';
const DOC_B = '55555555-5555-5555-5555-555555555552';

test('PostgreSQL 16 Full Package A Integration, RLS, Pool Isolation & Storage Gate', async (t) => {
  if (!DATABASE_URL || !APP_DATABASE_URL) {
    if (REQUIRE_PG) {
      assert.fail('GATE_BLOCKED: DATABASE_URL and APP_DATABASE_URL are required when REQUIRE_PG_INTEGRATION=true');
    }
    t.skip('PostgreSQL 16 env vars (DATABASE_URL / APP_DATABASE_URL) not configured in this local environment');
    return;
  }

  const { Pool } = await import('pg');
  const ownerPool = new Pool({ connectionString: DATABASE_URL, max: 2 });
  // max: 1 intentionally forces connection reuse to prove ZERO tenant context leakage across pool reuse!
  const appPool = new Pool({ connectionString: APP_DATABASE_URL, max: 1 });

  try {
    // 1. Apply Migrations 0001 -> 0002 -> 0003 in strict order on clean test schema
    await t.test('1. Apply Migrations 0001 -> 0002 -> 0003 in order', async () => {
      const migrations = [
        'db/migrations/0001_core_identity_rbac_rls.sql',
        'db/migrations/0002_auth_otp_mfa_rate_limits.sql',
        'db/migrations/0003_properties_documents_storage_rls.sql',
      ];
      for (const file of migrations) {
        const sql = fs.readFileSync(path.resolve(file), 'utf8');
        await ownerPool.query(sql);
      }
      // Ensure login role inherits aqar_app and has NOBYPASSRLS
      await ownerPool.query(`GRANT aqar_app TO aqar_app_login;`);
    });

    // 2. Verify aqar_app & aqar_app_login do NOT have BYPASSRLS or SUPERUSER
    await t.test('2. Verify aqar_app and aqar_app_login have NOBYPASSRLS and NOSUPERUSER', async () => {
      const { rows } = await ownerPool.query(
        `SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname IN ('aqar_app', 'aqar_app_login');`,
      );
      assert.ok(rows.length >= 2);
      for (const r of rows) {
        assert.equal(r.rolsuper, false, `${r.rolname} must NOT be superuser`);
        assert.equal(r.rolbypassrls, false, `${r.rolname} must NOT have BYPASSRLS`);
      }
    });

    // 3. Verify ENABLE RLS and FORCE RLS on all 16 protected tables
    await t.test('3. Verify ENABLE RLS and FORCE RLS on all tenant & security tables', async () => {
      const requiredRlsTables = [
        'organizations', 'memberships', 'roles', 'user_role_assignments',
        'permission_overrides', 'device_sessions', 'audit_logs', 'security_events',
        'mfa_recovery_codes', 'localities', 'properties', 'property_owners',
        'owner_authorizations', 'property_media', 'property_documents', 'property_status_history',
      ];
      const { rows } = await ownerPool.query(
        `SELECT relname, relrowsecurity, relforcerowsecurity
         FROM pg_class
         WHERE relname = ANY($1::text[]);`,
        [requiredRlsTables],
      );
      assert.equal(rows.length, requiredRlsTables.length);
      for (const r of rows) {
        assert.equal(r.relrowsecurity, true, `ENABLE RLS missing on ${r.relname}`);
        assert.equal(r.relforcerowsecurity, true, `FORCE RLS missing on ${r.relname}`);
      }
    });

    // 4. Seed two isolated organizations, users, memberships, roles, properties & private documents
    const keyA = generateOpaqueStorageKey({ organizationId: ORG_A, category: 'documents', extension: 'pdf' });
    const keyB = generateOpaqueStorageKey({ organizationId: ORG_B, category: 'documents', extension: 'pdf' });

    await t.test('4. Seed Org A & Org B isolated test fixtures', async () => {
      const client = await ownerPool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`SET LOCAL app.platform_admin = 'true';`);
        await client.query(
          `INSERT INTO organizations (id, name, slug, phone, status) VALUES
           ($1, 'مكتب النيل أ', 'nile-a', '+249911111111', 'active'),
           ($2, 'مكتب الخرطوم ب', 'khartoum-b', '+249922222222', 'active');`,
          [ORG_A, ORG_B],
        );
        await client.query(
          `INSERT INTO users (id, full_name, phone, mfa_enabled, status) VALUES
           ($1, 'مالك أ', '+249911111111', true, 'active'),
           ($2, 'مالك ب', '+249922222222', true, 'active');`,
          [USER_A, USER_B],
        );
        await client.query(
          `INSERT INTO memberships (id, user_id, organization_id, status, joined_at) VALUES
           ($1, $3, $5, 'active', now()),
           ($2, $4, $6, 'active', now());`,
          [MEM_A, MEM_B, USER_A, USER_B, ORG_A, ORG_B],
        );
        await client.query(
          `INSERT INTO user_role_assignments (organization_id, membership_id, role_id)
           SELECT $1, $2, id FROM roles WHERE key = 'owner' AND is_system = true;`,
          [ORG_A, MEM_A],
        );
        await client.query(
          `INSERT INTO user_role_assignments (organization_id, membership_id, role_id)
           SELECT $1, $2, id FROM roles WHERE key = 'owner' AND is_system = true;`,
          [ORG_B, MEM_B],
        );
        await client.query(
          `INSERT INTO properties (id, organization_id, property_type, purpose, area_m2, price_amount, currency_code, condition, title, status, created_by) VALUES
           ($1, $3, 'أرض', 'sale', 500.00, 120000.00, 'USD', 'intact', 'أرض مكتب أ', 'draft', $5),
           ($2, $4, 'بيت', 'sale', 300.00, 250000000.00, 'SDG', 'rehabilitated', 'بيت مكتب ب', 'draft', $6);`,
          [PROP_A, PROP_B, ORG_A, ORG_B, USER_A, USER_B],
        );
        await client.query(
          `INSERT INTO property_documents (id, organization_id, property_id, doc_type, private_storage_key, mime_type, size_bytes, checksum_sha256, created_by) VALUES
           ($1, $3, $5, 'title_deed', $7, 'application/pdf', 102400, 'sha-a', $9),
           ($2, $4, $6, 'title_deed', $8, 'application/pdf', 204800, 'sha-b', $10);`,
          [DOC_A, DOC_B, ORG_A, ORG_B, PROP_A, PROP_B, keyA, keyB, USER_A, USER_B],
        );
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    });

    // 5. Direct RLS Isolation & Cross-Tenant FK via non-privileged appPool (aqar_app_login)
    await t.test('5. Org A cannot read/update/delete Org B data or create cross-tenant FK', async () => {
      const client = await appPool.connect();
      try {
        await withTenantTransaction(client, { userId: USER_A, organizationId: ORG_A }, async (tx) => {
          const readB = await tx.query(`SELECT * FROM properties WHERE id = $1;`, [PROP_B]);
          assert.equal(readB.rowCount, 0);

          const updB = await tx.query(`UPDATE properties SET title = 'HACKED' WHERE id = $1;`, [PROP_B]);
          assert.equal(updB.rowCount, 0);

          const delB = await tx.query(`DELETE FROM properties WHERE id = $1;`, [PROP_B]);
          assert.equal(delB.rowCount, 0);

          await assert.rejects(
            () =>
              tx.query(
                `INSERT INTO property_documents (organization_id, property_id, doc_type, private_storage_key, mime_type, size_bytes, checksum_sha256, created_by)
                 VALUES ($1, $2, 'title_deed', $3, 'application/pdf', 1024, 'sha', $4);`,
                [ORG_A, PROP_B, keyA, USER_A],
              ),
            (err) => err.code === '23503', // PostgreSQL foreign_key_violation
          );
        });
      } finally {
        client.release();
      }
    });

    // 6. Connection Pool Isolation + Rollback Safety on max:1 Pool
    await t.test('6. Connection Pool reuse after Rollback leaks ZERO tenant context', async () => {
      const client1 = await appPool.connect();
      try {
        await assert.rejects(
          () =>
            withTenantTransaction(client1, { userId: USER_A, organizationId: ORG_A }, async (tx) => {
              const resA = await tx.query(`SELECT id FROM properties;`);
              assert.equal(resA.rows[0].id, PROP_A);
              throw new Error('INTENTIONAL_ROLLBACK_TEST');
            }),
          /INTENTIONAL_ROLLBACK_TEST/,
        );
      } finally {
        client1.release();
      }

      // Immediately reuse the exact same pooled connection for Org B
      const client2 = await appPool.connect();
      try {
        await withTenantTransaction(client2, { userId: USER_B, organizationId: ORG_B }, async (tx) => {
          const resB = await tx.query(`SELECT id, organization_id FROM properties;`);
          assert.equal(resB.rowCount, 1);
          assert.equal(resB.rows[0].id, PROP_B);
          assert.equal(resB.rows[0].organization_id, ORG_B);
        });
      } finally {
        client2.release();
      }
    });

    // 7. End-to-End API + OTP + PgRateLimitStore + Storage Signed URL against real PostgreSQL
    await t.test('7. Full Auth, OTP, Distributed Rate Limit & Private Storage API against PostgreSQL', async () => {
      const repo = new PgAuthRepository({ pool: appPool });
      const rateLimitStore = new PgRateLimitStore(appPool);
      const otpProvider = new TestOtpProvider('test');
      const authService = new AuthSessionService({ repo, rateLimitStore, otpProvider, secretPepper: PEPPER });
      const storageService = new PrivateStorageService({ signingSecret: SIGNING_SECRET });

      const authApi = createPackageAApiHandlers({ authService, repo, allowedOrigins: [ORIGIN] });
      const storageApi = createStorageApiHandlers({ authService, storageService, repo, allowedOrigins: [ORIGIN] });

      const t0 = new Date();
      const otpReq = await authApi.postAuthOtpRequest(
        { headers: { origin: ORIGIN }, ip: '196.10.10.1', body: { identifier: '+249911111111', deviceId: 'pg-dev-1' } },
        t0,
      );
      assert.equal(otpReq.status, 200);

      const otpCode = otpProvider.deliveries[0].code;
      const login = await authApi.postAuthOtpVerify(
        { headers: { origin: ORIGIN }, ip: '196.10.10.1', body: { identifier: '+249911111111', code: otpCode, deviceId: 'pg-dev-1', mfaVerified: true } },
        new Date(t0.getTime() + 2000),
      );
      assert.equal(login.status, 200);

      const map = {};
      for (const sc of login.headers['Set-Cookie']) {
        const [k, v] = sc.split(';')[0].split('=');
        map[k] = v;
      }
      const cookieHeader = `${SESSION_COOKIE_NAME}=${map[SESSION_COOKIE_NAME]}; ${CSRF_COOKIE_NAME}=${map[CSRF_COOKIE_NAME]}`;
      const csrfToken = map[CSRF_COOKIE_NAME];

      // Reuse OTP fails
      const reuse = await authApi.postAuthOtpVerify(
        { headers: { origin: ORIGIN }, ip: '196.10.10.1', body: { identifier: '+249911111111', code: otpCode, deviceId: 'pg-dev-1', mfaVerified: true } },
        new Date(t0.getTime() + 4000),
      );
      assert.equal(reuse.status, 401);

      // Org A gets signed URL for DOC_A -> succeeds & downloads
      const docARes = await storageApi.postIssueSignedUrl(
        { headers: { origin: ORIGIN, cookie: cookieHeader, 'x-csrf-token': csrfToken }, body: { fileId: DOC_A, fileKind: 'document' } },
        new Date(t0.getTime() + 5000),
      );
      assert.equal(docARes.status, 200);

      // Org A tries IDOR on DOC_B -> rejected (403)
      const docBRes = await storageApi.postIssueSignedUrl(
        { headers: { origin: ORIGIN, cookie: cookieHeader, 'x-csrf-token': csrfToken }, body: { fileId: DOC_B, fileKind: 'document' } },
        new Date(t0.getTime() + 6000),
      );
      assert.equal(docBRes.status, 403);
      assert.equal(docBRes.body.error.code, 'CROSS_TENANT_ACCESS_DENIED');
    });
  } finally {
    await appPool.end();
    await ownerPool.end();
  }
});
