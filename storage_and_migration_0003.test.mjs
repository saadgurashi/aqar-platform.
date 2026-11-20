import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

import {
  assertSafeStorageKey,
  generateOpaqueStorageKey,
  PrivateStorageService,
} from '../../src/shared/storage/private-storage.service.mjs';
import { AuthSessionService } from '../../src/modules/identity/auth-session.service.mjs';
import { TestOtpProvider } from '../../src/modules/identity/otp-provider.mjs';
import { InMemoryTestRateLimitStore } from '../../src/shared/auth/rate-limiter.mjs';
import { createPackageAApiHandlers } from '../../src/app/api/v1/handlers.mjs';
import { createStorageApiHandlers } from '../../src/app/api/v1/storage.handlers.mjs';
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME } from '../../src/shared/auth/cookies.mjs';
import { SYSTEM_ROLES } from '../../src/modules/authorization/permissions.mjs';

const sql0003 = fs
  .readFileSync(path.resolve('db/migrations/0003_properties_documents_storage_rls.sql'), 'utf8')
  .replace(/--.*$/gm, '');

const matrixSql = fs.readFileSync(path.resolve('tests/security/rls_isolation_matrix.sql'), 'utf8');

const PEPPER = 'aqar-2.0-test-pepper-at-least-32-chars!!';
const SIGNING_SECRET = 'aqar-2.0-storage-signing-secret-server-only!!';
const ORIGIN = 'https://aqar.sd';

const ORG_A = '11111111-1111-1111-1111-111111111111';
const ORG_B = '22222222-2222-2222-2222-222222222222';
const USER_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const MEM_A = '10000000-0000-0000-0000-000000000001';
const DOC_A_ID = '55555555-5555-5555-5555-555555555551';
const DOC_B_ID = '55555555-5555-5555-5555-555555555552';
const MEDIA_B_ID = '66666666-6666-6666-6666-666666666662';

test('Migration 0003 creates all 7 foundational tables with ENABLE & FORCE RLS', () => {
  const tables = [
    'localities',
    'properties',
    'property_owners',
    'owner_authorizations',
    'property_media',
    'property_documents',
    'property_status_history',
  ];

  for (const tbl of tables) {
    assert.match(sql0003, new RegExp(`CREATE TABLE ${tbl}\\b`, 'i'), `Missing CREATE TABLE ${tbl}`);
    assert.match(sql0003, new RegExp(`ALTER TABLE ${tbl} ENABLE ROW LEVEL SECURITY;`, 'i'), `Missing ENABLE RLS on ${tbl}`);
    assert.match(sql0003, new RegExp(`ALTER TABLE ${tbl} FORCE ROW LEVEL SECURITY;`, 'i'), `Missing FORCE RLS on ${tbl}`);
  }
});

test('Migration 0003 enforces composite cross-tenant FKs, forbids public URLs in private_storage_key, and avoids float', () => {
  assert.match(sql0003, /UNIQUE \(organization_id, id\)/i);
  assert.match(sql0003, /FOREIGN KEY \(organization_id, property_id\)\s+REFERENCES properties\(organization_id, id\)/i);
  assert.match(sql0003, /FOREIGN KEY \(organization_id, owner_id\)\s+REFERENCES property_owners\(organization_id, id\)/i);
  assert.match(sql0003, /private_storage_key NOT LIKE 'https:\/\/%'/i);
  assert.match(sql0003, /CREATE OR REPLACE VIEW public_property_listings/i);
  assert.doesNotMatch(sql0003, /\b(float4|float8|double precision|real)\b/i);
});

test('rls_isolation_matrix.sql covers all 10 isolation tests from Section 3.9', () => {
  for (let i = 1; i <= 10; i += 1) {
    assert.ok(matrixSql.includes(`[${i}/10]`), `Missing Section 3.9 test [${i}/10] in rls_isolation_matrix.sql`);
  }
  assert.match(matrixSql, /SET LOCAL ROLE aqar_app;/i);
});

test('Storage key validation rejects path traversal, leading slash, and public URLs', () => {
  const validKey = generateOpaqueStorageKey({ organizationId: ORG_A, category: 'documents', extension: 'pdf' });
  assert.doesNotThrow(() => assertSafeStorageKey(validKey));
  assert.throws(() => assertSafeStorageKey(`tenants/${ORG_A}/documents/../${ORG_B}/secret.pdf`), /UNSAFE_STORAGE_KEY/);
  assert.throws(() => assertSafeStorageKey('https://public-bucket.example/deed.pdf'), /UNSAFE_STORAGE_KEY/);
  assert.throws(() => assertSafeStorageKey('/etc/passwd'), /UNSAFE_STORAGE_KEY/);
});

test('Storage API enforces tenant isolation, short-lived signed URLs, tamper detection, and expiry', async () => {
  const keyA = generateOpaqueStorageKey({ organizationId: ORG_A, category: 'documents', extension: 'pdf' });
  const keyB = generateOpaqueStorageKey({ organizationId: ORG_B, category: 'documents', extension: 'pdf' });
  const mediaKeyB = generateOpaqueStorageKey({ organizationId: ORG_B, category: 'private-media', extension: 'jpg' });

  const privateFiles = new Map([
    [DOC_A_ID, { id: DOC_A_ID, organizationId: ORG_A, privateStorageKey: keyA }],
    [DOC_B_ID, { id: DOC_B_ID, organizationId: ORG_B, privateStorageKey: keyB }],
    [MEDIA_B_ID, { id: MEDIA_B_ID, organizationId: ORG_B, storageKey: mediaKeyB }],
  ]);

  const otpChallenges = [];
  const sessions = new Map();
  const auditLogs = [];
  const securityEvents = [];

  const repo = {
    async createOtpChallenge(rec) { otpChallenges.push({ ...rec }); return rec; },
    async findLatestOtpChallenge(h, p) { return [...otpChallenges].reverse().find((c) => c.identifierHash === h && c.purpose === p) ?? null; },
    async consumeOtpChallenge(id, now) { const c = otpChallenges.find((x) => x.id === id); if (c) c.consumedAt = now; },
    async findUserByIdentifier() { return { id: USER_A, fullName: 'مالك أ', phone: '+249911111111', status: 'active', mfaEnabled: true }; },
    async findUserById() { return { id: USER_A, fullName: 'مالك أ', phone: '+249911111111', status: 'active', mfaEnabled: true }; },
    async findActiveMembershipsForUser() { return [{ id: MEM_A, userId: USER_A, organizationId: ORG_A, status: 'active' }]; },
    async findMembership() { return { id: MEM_A, userId: USER_A, organizationId: ORG_A, status: 'active' }; },
    async findRoleKeysForMembership() { return [SYSTEM_ROLES.OWNER]; },
    async findPermissionOverrides() { return []; },
    async createSession(s) { sessions.set(s.id, { ...s }); return s; },
    async findSessionByTokenHash(h) { return [...sessions.values()].find((s) => s.tokenHash === h) ?? null; },
    async touchSession(id, ls, idle) { const s = sessions.get(id); if (s) { s.lastSeenAt = ls; s.idleTimeoutAt = idle; } },
    async findPrivateFileById(id) { return privateFiles.get(id) ?? null; },
    async recordLoginAttempt() {},
    async appendAuditLog(r) { auditLogs.push(r); },
    async recordSecurityEvent(r) { securityEvents.push(r); },
  };

  const otpProvider = new TestOtpProvider('test');
  const authService = new AuthSessionService({
    repo,
    rateLimitStore: new InMemoryTestRateLimitStore('test'),
    otpProvider,
    secretPepper: PEPPER,
  });
  const storageService = new PrivateStorageService({ signingSecret: SIGNING_SECRET });
  const authApi = createPackageAApiHandlers({ authService, repo, allowedOrigins: [ORIGIN] });
  const storageApi = createStorageApiHandlers({ authService, storageService, repo, allowedOrigins: [ORIGIN] });

  const t0 = new Date('2026-11-20T12:00:00Z');
  await authApi.postAuthOtpRequest({ headers: { origin: ORIGIN }, ip: '196.1.1.1', body: { identifier: '+249911111111', deviceId: 'dev-a' } }, t0);
  const login = await authApi.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.1.1.1', body: { identifier: '+249911111111', code: otpProvider.deliveries[0].code, deviceId: 'dev-a', mfaVerified: true } },
    t0,
  );

  const map = {};
  for (const sc of login.headers['Set-Cookie']) {
    const [k, v] = sc.split(';')[0].split('=');
    map[k] = v;
  }
  const cookieHeader = `${SESSION_COOKIE_NAME}=${map[SESSION_COOKIE_NAME]}; ${CSRF_COOKIE_NAME}=${map[CSRF_COOKIE_NAME]}`;
  const csrfToken = map[CSRF_COOKIE_NAME];

  // 1. Authorized User A requests Org A document -> gets short-lived signed URL (capped <= 300s)
  const okRes = await storageApi.postIssueSignedUrl(
    {
      headers: { origin: ORIGIN, cookie: cookieHeader, 'x-csrf-token': csrfToken },
      body: { fileId: DOC_A_ID, fileKind: 'document', ttlSeconds: 9999 }, // Even if client asks for 9999s, capped to 300s!
    },
    t0,
  );
  assert.equal(okRes.status, 200);
  assert.equal(okRes.body.ttlSeconds, 300);

  // Parse signed URL query params
  const parsedUrl = new URL(`https://aqar.sd${okRes.body.signedUrl}`);
  const queryObj = Object.fromEntries(parsedUrl.searchParams.entries());

  // 2. Valid signed URL before expiry succeeds
  const dlOk = await storageApi.getDownloadPrivateFile({ headers: {}, query: queryObj }, new Date(t0.getTime() + 60_000));
  assert.equal(dlOk.status, 200);
  assert.equal(dlOk.body.authorizedDownload, true);

  // 3. Tampering with fileId or storageKey fails signature verification (403)
  const dlTampered = await storageApi.getDownloadPrivateFile(
    { headers: {}, query: { ...queryObj, key: keyB } },
    new Date(t0.getTime() + 60_000),
  );
  assert.equal(dlTampered.status, 403);

  // 4. Expired signed URL fails (410)
  const dlExpired = await storageApi.getDownloadPrivateFile(
    { headers: {}, query: queryObj },
    new Date(t0.getTime() + 301_000),
  );
  assert.equal(dlExpired.status, 410);
  assert.equal(dlExpired.body.error.code, 'SIGNED_URL_EXPIRED');

  // 5. Cross-tenant IDOR: User A knowing Org B's exact documentId & private mediaId is blocked (403) & NO URL issued
  const idorDoc = await storageApi.postIssueSignedUrl(
    {
      headers: { origin: ORIGIN, cookie: cookieHeader, 'x-csrf-token': csrfToken },
      body: { fileId: DOC_B_ID, fileKind: 'document' },
    },
    t0,
  );
  assert.equal(idorDoc.status, 403);
  assert.equal(idorDoc.body.error.code, 'CROSS_TENANT_ACCESS_DENIED');
  assert.equal('signedUrl' in idorDoc.body, false);

  const idorMedia = await storageApi.postIssueSignedUrl(
    {
      headers: { origin: ORIGIN, cookie: cookieHeader, 'x-csrf-token': csrfToken },
      body: { fileId: MEDIA_B_ID, fileKind: 'private_media' },
    },
    t0,
  );
  assert.equal(idorMedia.status, 403);
  assert.equal(idorMedia.body.error.code, 'CROSS_TENANT_ACCESS_DENIED');
});
