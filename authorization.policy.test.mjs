import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ALL_PERMISSION_KEYS,
  PERMISSIONS,
  SYSTEM_ROLES,
} from '../../src/modules/authorization/permissions.mjs';
import { evaluateAuthorization } from '../../src/modules/authorization/policy.service.mjs';
import { withTenantTransaction } from '../../src/shared/db/tenant-context.mjs';
import { sanitizeAuditPayload } from '../../src/shared/audit/sanitizer.mjs';

const ORG_A = '11111111-1111-1111-1111-111111111111';
const ORG_B = '22222222-2222-2222-2222-222222222222';
const USER_A = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const USER_OTHER = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const MEM_A = 'aaaa1111-1111-1111-1111-111111111111';

const NOW = new Date('2026-11-20T12:00:00Z');
const FUTURE = new Date('2026-11-21T12:00:00Z');
const PAST = new Date('2026-11-19T12:00:00Z');

function baseInput(overrides = {}) {
  return {
    session: {
      id: 'sess-1',
      activeOrganizationId: ORG_A,
      expiresAt: FUTURE,
      revokedAt: null,
    },
    user: {
      id: USER_A,
      status: 'active',
      mfaEnabled: true,
    },
    membership: {
      id: MEM_A,
      userId: USER_A,
      organizationId: ORG_A,
      status: 'active',
    },
    roles: [SYSTEM_ROLES.OWNER],
    overrides: [],
    requiredPermission: PERMISSIONS.PROPERTIES_VIEW,
    now: NOW,
    ...overrides,
  };
}

test('1. Permission Registry includes all required keys from Section 3.3 & 5.2', () => {
  assert.ok(ALL_PERMISSION_KEYS.length >= 37);
  assert.ok(ALL_PERMISSION_KEYS.includes('properties.verify'));
  assert.ok(ALL_PERMISSION_KEYS.includes('finance.ledger.post'));
  assert.ok(ALL_PERMISSION_KEYS.includes('organization.settings.manage'));
});

test('2. Rejects client-supplied organization_id spoofing (Section 2 & 3.4)', () => {
  const res = evaluateAuthorization(
    baseInput({
      claimedOrganizationId: ORG_B,
    }),
  );
  assert.equal(res.allowed, false);
  assert.equal(res.reasonCode, 'TENANT_CONTEXT_MISMATCH');
  assert.equal(res.securityEvent?.severity, 'critical');
});

test('3. Rejects cross-tenant resource access (IDOR protection)', () => {
  const res = evaluateAuthorization(
    baseInput({
      resource: { organizationId: ORG_B },
    }),
  );
  assert.equal(res.allowed, false);
  assert.equal(res.reasonCode, 'CROSS_TENANT_ACCESS_DENIED');
  assert.equal(res.securityEvent?.eventType, 'security.cross_tenant_idor_attempt');
});

test('4. Rejects revoked or expired sessions and suspended memberships', () => {
  const revoked = evaluateAuthorization(
    baseInput({ session: { id: 's1', activeOrganizationId: ORG_A, expiresAt: FUTURE, revokedAt: PAST } }),
  );
  assert.equal(revoked.allowed, false);
  assert.equal(revoked.reasonCode, 'SESSION_REVOKED');

  const expired = evaluateAuthorization(
    baseInput({ session: { id: 's1', activeOrganizationId: ORG_A, expiresAt: PAST, revokedAt: null } }),
  );
  assert.equal(expired.allowed, false);
  assert.equal(expired.reasonCode, 'SESSION_EXPIRED');

  const suspended = evaluateAuthorization(
    baseInput({ membership: { id: MEM_A, userId: USER_A, organizationId: ORG_A, status: 'suspended' } }),
  );
  assert.equal(suspended.allowed, false);
  assert.equal(suspended.reasonCode, 'MEMBERSHIP_INACTIVE');
});

test('5. Enforces mandatory MFA for Owner, Manager, and Platform Admin (Section 3.10)', () => {
  const res = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.OWNER],
    }),
  );
  assert.equal(res.allowed, false);
  assert.equal(res.reasonCode, 'MFA_REQUIRED');
});

test('6. Prevents role escalation (Agent cannot manage roles or org settings)', () => {
  const res = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.AGENT],
      requiredPermission: PERMISSIONS.ROLES_MANAGE,
    }),
  );
  assert.equal(res.allowed, false);
  assert.equal(res.reasonCode, 'FORBIDDEN');
});

test('7. Enforces ownership scope: Agent can update own property but not another agent property', () => {
  const own = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.AGENT],
      requiredPermission: PERMISSIONS.PROPERTIES_UPDATE_OWN,
      resource: { organizationId: ORG_A, ownerUserId: USER_A },
    }),
  );
  assert.equal(own.allowed, true);

  const other = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.AGENT],
      requiredPermission: PERMISSIONS.PROPERTIES_UPDATE_OWN,
      resource: { organizationId: ORG_A, ownerUserId: USER_OTHER },
    }),
  );
  assert.equal(other.allowed, false);
  assert.equal(other.reasonCode, 'OWNERSHIP_REQUIRED');
});

test('8. Temporary permission_overrides: active allow/deny respected, expired ignored', () => {
  const activeAllow = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.VIEWER],
      overrides: [{ permissionKey: PERMISSIONS.REPORTS_EXPORT, effect: 'allow', expiresAt: FUTURE }],
      requiredPermission: PERMISSIONS.REPORTS_EXPORT,
    }),
  );
  assert.equal(activeAllow.allowed, true);

  const expiredAllow = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.VIEWER],
      overrides: [{ permissionKey: PERMISSIONS.REPORTS_EXPORT, effect: 'allow', expiresAt: PAST }],
      requiredPermission: PERMISSIONS.REPORTS_EXPORT,
    }),
  );
  assert.equal(expiredAllow.allowed, false);

  const activeDeny = evaluateAuthorization(
    baseInput({
      roles: [SYSTEM_ROLES.OWNER],
      overrides: [{ permissionKey: PERMISSIONS.FINANCE_REFUNDS_APPROVE, effect: 'deny', expiresAt: FUTURE }],
      requiredPermission: PERMISSIONS.FINANCE_REFUNDS_APPROVE,
    }),
  );
  assert.equal(activeDeny.allowed, false);
  assert.equal(activeDeny.reasonCode, 'EXPLICIT_DENY_OVERRIDE');
});

test('9. Separation of Duties (SoD): creator cannot confirm own payment (Section 3.2 & 7.4)', () => {
  const selfConfirm = evaluateAuthorization(
    baseInput({
      roles: [SYSTEM_ROLES.ACCOUNTANT],
      requiredPermission: PERMISSIONS.FINANCE_PAYMENTS_CONFIRM,
      resource: { organizationId: ORG_A, createdByUserId: USER_A },
      orgRequiresPaymentSod: true,
    }),
  );
  assert.equal(selfConfirm.allowed, false);
  assert.equal(selfConfirm.reasonCode, 'SOD_CONFLICT_OF_DUTIES');

  const otherConfirm = evaluateAuthorization(
    baseInput({
      roles: [SYSTEM_ROLES.ACCOUNTANT],
      requiredPermission: PERMISSIONS.FINANCE_PAYMENTS_CONFIRM,
      resource: { organizationId: ORG_A, createdByUserId: USER_OTHER },
      orgRequiresPaymentSod: true,
    }),
  );
  assert.equal(otherConfirm.allowed, true);
});

test('10. Verification Officer cannot approve financial payments (Section 3.2)', () => {
  const res = evaluateAuthorization(
    baseInput({
      user: { id: USER_A, status: 'active', mfaEnabled: false },
      roles: [SYSTEM_ROLES.VERIFICATION_OFFICER],
      requiredPermission: PERMISSIONS.FINANCE_PAYMENTS_CONFIRM,
    }),
  );
  assert.equal(res.allowed, false);
  assert.equal(res.reasonCode, 'FORBIDDEN');
});

test('11. Audit sanitizer redacts OTP, passwords, tokens, and recovery codes', () => {
  const sanitized = sanitizeAuditPayload({
    phone: '+249911111111',
    otp_code: '482910',
    password_hash: 'argon2id$...',
    nested: { refresh_token: 'tok_secret_123', recovery_code: 'REC-999' },
  });
  assert.equal(sanitized.phone, '+249911111111');
  assert.equal(sanitized.otp_code, '[REDACTED]');
  assert.equal(sanitized.password_hash, '[REDACTED]');
  assert.equal(sanitized.nested.refresh_token, '[REDACTED]');
  assert.equal(sanitized.nested.recovery_code, '[REDACTED]');
});

test('12. Tenant DB transaction wrapper sets transaction-local RLS context & fails closed', async () => {
  const executed = [];
  const fakeClient = {
    async query(sql, params) {
      executed.push({ sql, params });
      return { rows: [] };
    },
  };

  await assert.rejects(
    () => withTenantTransaction(fakeClient, { userId: USER_A, organizationId: '' }, async () => {}),
    /FAIL_CLOSED/,
  );

  const out = await withTenantTransaction(
    fakeClient,
    { userId: USER_A, organizationId: ORG_A },
    async () => 'ok',
  );
  assert.equal(out, 'ok');
  assert.equal(executed[0].sql, 'BEGIN');
  assert.match(executed[1].sql, /set_config\('app\.user_id', \$1, true\)/);
  assert.match(executed[2].sql, /set_config\('app\.organization_id', \$1, true\)/);
  assert.equal(executed.at(-1).sql, 'COMMIT');
});
