/**
 * Server-Side API Security Guard — منصة عقار 2.0 (Section 3.4, 3.10, 11)
 *
 * Enforces on every protected API route:
 * 1. Correlation ID (`X-Request-Id`).
 * 2. Strict Origin + CSRF verification for state-changing HTTP methods.
 * 3. HttpOnly Cookie session resolution (idle timeout + max expiry + revocation).
 * 4. Rejection of client-supplied organization_id / user_id / role spoofing.
 * 5. Server-side RBAC + MFA + Ownership + SoD via evaluateAuthorization().
 * 6. Unified non-leaking error responses.
 */

import { randomUUID } from 'node:crypto';
import { parseCookieHeader, SESSION_COOKIE_NAME } from './cookies.mjs';
import { getHeader, verifyCsrfAndOrigin } from './csrf.mjs';
import { evaluateAuthorization } from '../../modules/authorization/policy.service.mjs';

export async function guardProtectedRequest({
  req,
  authService,
  repo,
  allowedOrigins,
  requiredPermission,
  resource = undefined,
  now = new Date(),
}) {
  const requestId = getHeader(req.headers, 'x-request-id') || randomUUID();
  const cookies = parseCookieHeader(getHeader(req.headers, 'cookie'));
  const rawSessionToken = cookies[SESSION_COOKIE_NAME];

  const resolved = await authService.resolveSessionFromToken(rawSessionToken, now);
  if (!resolved.ok) {
    return {
      ok: false,
      status: 401,
      headers: { 'X-Request-Id': requestId },
      body: { error: { code: resolved.code, message: 'يلزم تسجيل الدخول بجلسة صالحة', requestId } },
    };
  }

  const session = resolved.session;

  // Enforce Origin + CSRF on state-changing requests bound to the active session's csrfTokenHash
  const csrf = verifyCsrfAndOrigin({
    method: req.method,
    headers: req.headers,
    allowedOrigins,
    expectedCsrfTokenHash: session.csrfTokenHash,
    pepper: authService.pepper,
    requireCsrfToken: true,
  });

  if (!csrf.ok) {
    await repo.recordSecurityEvent({
      organizationId: session.activeOrganizationId,
      userId: session.userId,
      eventType: 'security.csrf_blocked',
      severity: 'high',
      details: { code: csrf.code, method: req.method },
      requestId,
      createdAt: now,
    });
    return {
      ok: false,
      status: 403,
      headers: { 'X-Request-Id': requestId },
      body: { error: { code: csrf.code, message: csrf.message, requestId } },
    };
  }

  // Detect client spoofing of organization_id, user_id, or role in body/headers
  const claimedOrgId =
    getHeader(req.headers, 'x-organization-id') ||
    req.body?.organization_id ||
    req.body?.organizationId ||
    req.query?.organization_id ||
    undefined;

  const claimedUserId =
    getHeader(req.headers, 'x-user-id') ||
    req.body?.actor_user_id ||
    undefined;

  if (claimedUserId && claimedUserId !== session.userId) {
    await repo.recordSecurityEvent({
      organizationId: session.activeOrganizationId,
      userId: session.userId,
      eventType: 'security.user_spoofing_attempt',
      severity: 'critical',
      details: { claimedUserId },
      requestId,
      createdAt: now,
    });
    return {
      ok: false,
      status: 403,
      headers: { 'X-Request-Id': requestId },
      body: { error: { code: 'USER_CONTEXT_MISMATCH', message: 'رفض الوصول', requestId } },
    };
  }

  const user = await repo.findUserById(session.userId);
  const membership = session.activeOrganizationId
    ? await repo.findMembership(session.userId, session.activeOrganizationId)
    : null;
  const roles = membership
    ? await repo.findRoleKeysForMembership(membership.id, membership.organizationId)
    : [];
  const overrides = membership
    ? await repo.findPermissionOverrides(membership.id, membership.organizationId)
    : [];

  const decision = evaluateAuthorization({
    session,
    user,
    membership,
    roles,
    overrides,
    requiredPermission,
    claimedOrganizationId: claimedOrgId,
    resource,
    now,
  });

  if (!decision.allowed) {
    if (decision.securityEvent) {
      await repo.recordSecurityEvent({
        organizationId: session.activeOrganizationId,
        userId: session.userId,
        eventType: decision.securityEvent.eventType,
        severity: decision.securityEvent.severity,
        details: decision.securityEvent.details,
        requestId,
        createdAt: now,
      });
    }
    return {
      ok: false,
      status: decision.reasonCode === 'UNAUTHENTICATED' ? 401 : 403,
      headers: { 'X-Request-Id': requestId },
      body: {
        error: {
          code: decision.reasonCode,
          message: decision.message,
          requestId,
        },
      },
    };
  }

  return {
    ok: true,
    requestId,
    session,
    user,
    membership,
    roles,
    verifiedContext: decision.verifiedContext,
  };
}
