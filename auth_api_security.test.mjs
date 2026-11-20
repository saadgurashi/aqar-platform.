import test from 'node:test';
import assert from 'node:assert/strict';

import { AuthSessionService } from '../../src/modules/identity/auth-session.service.mjs';
import { TestOtpProvider, UnconfiguredOtpProvider } from '../../src/modules/identity/otp-provider.mjs';
import { InMemoryTestRateLimitStore } from '../../src/shared/auth/rate-limiter.mjs';
import { createPackageAApiHandlers } from '../../src/app/api/v1/handlers.mjs';
import { CSRF_COOKIE_NAME, SESSION_COOKIE_NAME } from '../../src/shared/auth/cookies.mjs';
import { SYSTEM_ROLES } from '../../src/modules/authorization/permissions.mjs';

const PEPPER = 'aqar-2.0-test-pepper-at-least-32-chars!!';
const ORIGIN = 'https://aqar.sd';

const ORG_A = '11111111-1111-1111-1111-111111111111';
const ORG_B = '22222222-2222-2222-2222-222222222222';
const OWNER_A_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const AGENT_A_ID = 'aaaa2222-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const OWNER_NOMFA_ID = 'aaaa3333-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const OWNER_B_ID = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

const MEM_OWNER_A = '10000000-0000-0000-0000-000000000001';
const MEM_AGENT_A = '10000000-0000-0000-0000-000000000002';
const MEM_NOMFA_A = '10000000-0000-0000-0000-000000000003';
const MEM_OWNER_B = '20000000-0000-0000-0000-000000000001';

/** In-memory test repository strictly for unit/API security verification (NOT a PostgreSQL replacement) */
function createTestRepo() {
  const users = new Map([
    [OWNER_A_ID, { id: OWNER_A_ID, fullName: 'مالك مكتب أ', phone: '+249911111111', status: 'active', mfaEnabled: true }],
    [AGENT_A_ID, { id: AGENT_A_ID, fullName: 'وسيط مكتب أ', phone: '+249911111112', status: 'active', mfaEnabled: false }],
    [OWNER_NOMFA_ID, { id: OWNER_NOMFA_ID, fullName: 'مالك بلا MFA', phone: '+249911111113', status: 'active', mfaEnabled: false }],
    [OWNER_B_ID, { id: OWNER_B_ID, fullName: 'مالك مكتب ب', phone: '+249922222221', status: 'active', mfaEnabled: true }],
  ]);

  const memberships = new Map([
    [MEM_OWNER_A, { id: MEM_OWNER_A, userId: OWNER_A_ID, organizationId: ORG_A, status: 'active' }],
    [MEM_AGENT_A, { id: MEM_AGENT_A, userId: AGENT_A_ID, organizationId: ORG_A, status: 'active' }],
    [MEM_NOMFA_A, { id: MEM_NOMFA_A, userId: OWNER_NOMFA_ID, organizationId: ORG_A, status: 'active' }],
    [MEM_OWNER_B, { id: MEM_OWNER_B, userId: OWNER_B_ID, organizationId: ORG_B, status: 'active' }],
  ]);

  const memberRoles = new Map([
    [MEM_OWNER_A, [SYSTEM_ROLES.OWNER]],
    [MEM_AGENT_A, [SYSTEM_ROLES.AGENT]],
    [MEM_NOMFA_A, [SYSTEM_ROLES.OWNER]],
    [MEM_OWNER_B, [SYSTEM_ROLES.OWNER]],
  ]);

  const otpChallenges = [];
  const sessions = new Map();
  const auditLogs = [];
  const securityEvents = [];
  const loginAttempts = [];

  return {
    otpChallenges,
    sessions,
    auditLogs,
    securityEvents,
    loginAttempts,
    async createOtpChallenge(rec) { otpChallenges.push({ ...rec }); return rec; },
    async findLatestOtpChallenge(identifierHash, purpose) {
      return [...otpChallenges].reverse().find((c) => c.identifierHash === identifierHash && c.purpose === purpose) ?? null;
    },
    async incrementOtpAttempts(id, attempts, consumedAt) {
      const c = otpChallenges.find((x) => x.id === id);
      if (c) { c.attempts = attempts; if (consumedAt) c.consumedAt = consumedAt; }
    },
    async consumeOtpChallenge(id, now) {
      const c = otpChallenges.find((x) => x.id === id);
      if (c) c.consumedAt = now;
    },
    async findUserByIdentifier(identifier) {
      return [...users.values()].find((u) => u.phone === identifier) ?? null;
    },
    async findUserById(id) { return users.get(id) ?? null; },
    async findActiveMembershipsForUser(userId) {
      return [...memberships.values()].filter((m) => m.userId === userId && m.status === 'active');
    },
    async findMembership(userId, orgId) {
      return [...memberships.values()].find((m) => m.userId === userId && m.organizationId === orgId) ?? null;
    },
    async findMembershipById(id) { return memberships.get(id) ?? null; },
    async listMembershipsByOrg(orgId) {
      return [...memberships.values()].filter((m) => m.organizationId === orgId);
    },
    async updateMembershipStatus(id, orgId, status) {
      const m = memberships.get(id);
      if (m && m.organizationId === orgId) m.status = status;
    },
    async findRoleKeysForMembership(memId) { return memberRoles.get(memId) ?? []; },
    async assignRoleToMembership(memId, _orgId, roleKey) {
      const existing = memberRoles.get(memId) ?? [];
      if (!existing.includes(roleKey)) memberRoles.set(memId, [...existing, roleKey]);
    },
    async findPermissionOverrides() { return []; },
    async createSession(s) { sessions.set(s.id, { ...s }); return s; },
    async findSessionByTokenHash(hash) {
      return [...sessions.values()].find((s) => s.tokenHash === hash) ?? null;
    },
    async touchSession(id, lastSeenAt, idleTimeoutAt) {
      const s = sessions.get(id);
      if (s) { s.lastSeenAt = lastSeenAt; s.idleTimeoutAt = idleTimeoutAt; }
    },
    async revokeSession(id, reason, now) {
      const s = sessions.get(id);
      if (s) { s.revokedAt = now; s.revokedReason = reason; }
    },
    async revokeUserSessionsForOrg(userId, orgId, reason, now) {
      let count = 0;
      for (const s of sessions.values()) {
        if (s.userId === userId && s.activeOrganizationId === orgId && !s.revokedAt) {
          s.revokedAt = now;
          s.revokedReason = reason;
          count += 1;
        }
      }
      return count;
    },
    async consumeMfaRecoveryCode() { return false; },
    async recordLoginAttempt(rec) { loginAttempts.push(rec); },
    async appendAuditLog(rec) { auditLogs.push(rec); },
    async recordSecurityEvent(rec) { securityEvents.push(rec); },
  };
}

function extractCookiePair(setCookies) {
  const map = {};
  for (const sc of setCookies) {
    const [pair] = sc.split(';');
    const [k, v] = pair.split('=');
    map[k] = v;
  }
  return {
    cookieHeader: `${SESSION_COOKIE_NAME}=${map[SESSION_COOKIE_NAME]}; ${CSRF_COOKIE_NAME}=${map[CSRF_COOKIE_NAME]}`,
    sessionToken: map[SESSION_COOKIE_NAME],
    csrfToken: map[CSRF_COOKIE_NAME],
  };
}

function setupHarness() {
  const repo = createTestRepo();
  const rateLimitStore = new InMemoryTestRateLimitStore('test');
  const otpProvider = new TestOtpProvider('test');
  const authService = new AuthSessionService({
    repo,
    rateLimitStore,
    otpProvider,
    secretPepper: PEPPER,
  });
  const api = createPackageAApiHandlers({ authService, repo, allowedOrigins: [ORIGIN] });
  return { repo, rateLimitStore, otpProvider, authService, api };
}

test('1. OTP cannot be reused, cannot be used after expiry, and is NEVER stored/logged in plaintext', async () => {
  const { repo, otpProvider, api } = setupHarness();
  const t0 = new Date('2026-11-20T10:00:00Z');

  const reqRes = await api.postAuthOtpRequest(
    { headers: { origin: ORIGIN }, ip: '196.1.1.1', body: { identifier: '+249911111111', deviceId: 'dev-1' } },
    t0,
  );
  assert.equal(reqRes.status, 200);
  const otp = otpProvider.deliveries[0].code;

  // Verify OTP is never stored in plaintext anywhere in repo or audit logs
  assert.equal(JSON.stringify(repo.otpChallenges).includes(otp), false);
  assert.equal(JSON.stringify(repo.auditLogs).includes(otp), false);

  // First verify succeeds & sets HttpOnly Secure SameSite cookies without leaking session token in JSON body
  const ver1 = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.1.1.1', body: { identifier: '+249911111111', code: otp, deviceId: 'dev-1', mfaVerified: true } },
    new Date(t0.getTime() + 10_000),
  );
  assert.equal(ver1.status, 200);
  assert.ok(ver1.headers['Set-Cookie'][0].includes('HttpOnly'));
  assert.ok(ver1.headers['Set-Cookie'][0].includes('Secure'));
  assert.ok(ver1.headers['Set-Cookie'][0].includes('SameSite=Lax'));
  assert.equal('sessionToken' in ver1.body, false);

  // Second reuse of same OTP MUST fail
  const ver2 = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.1.1.1', body: { identifier: '+249911111111', code: otp, deviceId: 'dev-1', mfaVerified: true } },
    new Date(t0.getTime() + 15_000),
  );
  assert.equal(ver2.status, 401);
  assert.equal(ver2.body.error.code, 'OTP_ALREADY_USED');

  // Expired OTP MUST fail
  await api.postAuthOtpRequest(
    { headers: { origin: ORIGIN }, ip: '196.1.1.2', body: { identifier: '+249911111112', deviceId: 'dev-2' } },
    t0,
  );
  const expiredOtp = otpProvider.deliveries[1].code;
  const verExpired = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.1.1.2', body: { identifier: '+249911111112', code: expiredOtp, deviceId: 'dev-2' } },
    new Date(t0.getTime() + 301_000), // > 5 minutes
  );
  assert.equal(verExpired.status, 401);
  assert.equal(verExpired.body.error.code, 'OTP_EXPIRED');
});

test('2. Multi-dimensional Rate Limiting blocks OTP guessing across Account, IP, and Device', async () => {
  const { api } = setupHarness();
  const t0 = new Date('2026-11-20T10:00:00Z');

  await api.postAuthOtpRequest(
    { headers: { origin: ORIGIN }, ip: '196.2.2.2', body: { identifier: '+249911111112', deviceId: 'dev-brute' } },
    t0,
  );

  // 5 wrong attempts trigger max_attempts / rate limit (429)
  let hit429 = false;
  for (let i = 0; i < 6; i += 1) {
    const res = await api.postAuthOtpVerify(
      { headers: { origin: ORIGIN }, ip: '196.2.2.2', body: { identifier: '+249911111112', code: '000000', deviceId: 'dev-brute' } },
      new Date(t0.getTime() + i * 1000),
    );
    if (res.status === 429) hit429 = true;
  }
  assert.equal(hit429, true);
});

test('3. Production guards: InMemoryTestRateLimitStore & UnconfiguredOtpProvider fail closed', async () => {
  assert.throws(() => new InMemoryTestRateLimitStore('production'), /SECURITY_POLICY_VIOLATION/);
  const unconfigured = new UnconfiguredOtpProvider();
  await assert.rejects(() => unconfigured.sendOtp({ destination: '+249911111111', code: '123456' }), /OTP_PROVIDER_NOT_CONFIGURED/);
});

test('4. MFA is strictly enforced for Owner and cannot be bypassed via direct API calls', async () => {
  const { otpProvider, api } = setupHarness();
  const t0 = new Date('2026-11-20T10:00:00Z');

  await api.postAuthOtpRequest(
    { headers: { origin: ORIGIN }, ip: '196.3.3.3', body: { identifier: '+249911111113', deviceId: 'dev-nomfa' } },
    t0,
  );
  const otp = otpProvider.deliveries[0].code;

  const verifyRes = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.3.3.3', body: { identifier: '+249911111113', code: otp, deviceId: 'dev-nomfa', mfaVerified: false } },
    t0,
  );
  assert.equal(verifyRes.status, 403);
  assert.equal(verifyRes.body.error.code, 'MFA_REQUIRED');
});

test('5. CSRF & Origin checks block forged mutating requests while valid CSRF succeeds', async () => {
  const { otpProvider, api } = setupHarness();
  const t0 = new Date('2026-11-20T10:00:00Z');

  await api.postAuthOtpRequest(
    { headers: { origin: ORIGIN }, ip: '196.4.4.4', body: { identifier: '+249911111111', deviceId: 'dev-owner' } },
    t0,
  );
  const login = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.4.4.4', body: { identifier: '+249911111111', code: otpProvider.deliveries[0].code, deviceId: 'dev-owner', mfaVerified: true } },
    t0,
  );
  const { cookieHeader, csrfToken } = extractCookiePair(login.headers['Set-Cookie']);

  // Untrusted Origin -> 403
  const badOrigin = await api.postAuthRotateSession(
    { headers: { origin: 'https://evil.example', cookie: cookieHeader, 'x-csrf-token': csrfToken } },
    t0,
  );
  assert.equal(badOrigin.status, 403);
  assert.equal(badOrigin.body.error.code, 'CSRF_UNTRUSTED_ORIGIN');

  // Missing CSRF token -> 403
  const noCsrf = await api.postAuthRotateSession(
    { headers: { origin: ORIGIN, cookie: cookieHeader } },
    t0,
  );
  assert.equal(noCsrf.status, 403);
  assert.equal(noCsrf.body.error.code, 'CSRF_TOKEN_MISMATCH');

  // Valid Origin + CSRF rotates session and invalidates old session cookie immediately!
  const rotated = await api.postAuthRotateSession(
    { headers: { origin: ORIGIN, cookie: cookieHeader, 'x-csrf-token': csrfToken } },
    t0,
  );
  assert.equal(rotated.status, 200);

  const reuseOld = await api.getRoles({ headers: { cookie: cookieHeader } }, t0);
  assert.equal(reuseOld.status, 401);
  assert.equal(reuseOld.body.error.code, 'SESSION_REVOKED');
});

test('6. IDOR, cross-tenant spoofing, privilege escalation, and suspension revocation all fail closed', async () => {
  const { otpProvider, api } = setupHarness();
  const t0 = new Date('2026-11-20T10:00:00Z');

  // Login Owner A & Agent A
  await api.postAuthOtpRequest({ headers: { origin: ORIGIN }, ip: '196.5.5.1', body: { identifier: '+249911111111', deviceId: 'dev-oa' } }, t0);
  const ownerLogin = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.5.5.1', body: { identifier: '+249911111111', code: otpProvider.deliveries[0].code, deviceId: 'dev-oa', mfaVerified: true } },
    t0,
  );
  const ownerAuth = extractCookiePair(ownerLogin.headers['Set-Cookie']);

  await api.postAuthOtpRequest({ headers: { origin: ORIGIN }, ip: '196.5.5.2', body: { identifier: '+249911111112', deviceId: 'dev-aa' } }, t0);
  const agentLogin = await api.postAuthOtpVerify(
    { headers: { origin: ORIGIN }, ip: '196.5.5.2', body: { identifier: '+249911111112', code: otpProvider.deliveries[1].code, deviceId: 'dev-aa' } },
    t0,
  );
  const agentAuth = extractCookiePair(agentLogin.headers['Set-Cookie']);

  // A. Owner A tries IDOR: suspending Org B's membership -> 403 CROSS_TENANT_ACCESS_DENIED
  const idorRes = await api.postSuspendMembership(
    {
      headers: { origin: ORIGIN, cookie: ownerAuth.cookieHeader, 'x-csrf-token': ownerAuth.csrfToken },
      body: { membershipId: MEM_OWNER_B, reason: 'idor attempt' },
    },
    t0,
  );
  assert.equal(idorRes.status, 403);
  assert.equal(idorRes.body.error.code, 'CROSS_TENANT_ACCESS_DENIED');

  // B. Owner A tries spoofing x-organization-id header to Org B -> 403 TENANT_CONTEXT_MISMATCH
  const spoofRes = await api.getMemberships(
    { headers: { cookie: ownerAuth.cookieHeader, 'x-organization-id': ORG_B } },
    t0,
  );
  assert.equal(spoofRes.status, 403);
  assert.equal(spoofRes.body.error.code, 'TENANT_CONTEXT_MISMATCH');

  // C. Agent A tries privilege escalation (assigning self owner role) -> 403 FORBIDDEN
  const escRes = await api.postAssignRole(
    {
      headers: { origin: ORIGIN, cookie: agentAuth.cookieHeader, 'x-csrf-token': agentAuth.csrfToken },
      body: { membershipId: MEM_AGENT_A, roleKey: SYSTEM_ROLES.OWNER },
    },
    t0,
  );
  assert.equal(escRes.status, 403);
  assert.equal(escRes.body.error.code, 'FORBIDDEN');

  // D. Owner A suspends Agent A -> Agent A's existing session is immediately revoked (401)
  const suspRes = await api.postSuspendMembership(
    {
      headers: { origin: ORIGIN, cookie: ownerAuth.cookieHeader, 'x-csrf-token': ownerAuth.csrfToken },
      body: { membershipId: MEM_AGENT_A, reason: 'مخالفة سياسة المكتب' },
    },
    t0,
  );
  assert.equal(suspRes.status, 200);
  assert.equal(suspRes.body.revokedSessions, 1);

  const agentAfterSuspension = await api.postAuthLogout(
    { headers: { origin: ORIGIN, cookie: agentAuth.cookieHeader, 'x-csrf-token': agentAuth.csrfToken } },
    t0,
  );
  assert.equal(agentAfterSuspension.status, 401);
  assert.equal(agentAfterSuspension.body.error.code, 'SESSION_REVOKED');

  // E. Idle timeout (> 30 min) rejects Owner A's session
  const afterIdle = await api.getPermissions(
    { headers: { cookie: ownerAuth.cookieHeader } },
    new Date(t0.getTime() + 31 * 60 * 1000),
  );
  assert.equal(afterIdle.status, 401);
  assert.equal(afterIdle.body.error.code, 'SESSION_IDLE_TIMEOUT');
});
