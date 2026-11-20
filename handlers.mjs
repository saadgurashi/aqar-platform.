/**
 * API v1 Route Handlers for Package A (Identity, Sessions, Memberships, Roles, Permissions)
 * Reference: منصة عقار 2.0 — Section 11
 *
 * Routes implemented:
 * - POST /api/v1/auth/otp/request
 * - POST /api/v1/auth/otp/verify
 * - POST /api/v1/auth/logout
 * - POST /api/v1/auth/sessions/rotate
 * - GET  /api/v1/memberships
 * - POST /api/v1/memberships/suspend
 * - GET  /api/v1/roles
 * - POST /api/v1/roles/assign
 * - GET  /api/v1/permissions
 */

import { randomUUID } from 'node:crypto';
import { getHeader, verifyCsrfAndOrigin } from '../../../shared/auth/csrf.mjs';
import { guardProtectedRequest } from '../../../shared/auth/api-guard.mjs';
import { ALL_PERMISSION_KEYS, PERMISSIONS, SYSTEM_ROLES } from '../../../modules/authorization/permissions.mjs';

export function createPackageAApiHandlers({ authService, repo, allowedOrigins = ['https://aqar.sd'] }) {
  return {
    async postAuthOtpRequest(req, now = new Date()) {
      const requestId = getHeader(req.headers, 'x-request-id') || randomUUID();
      const originCheck = verifyCsrfAndOrigin({
        method: 'POST',
        headers: req.headers,
        allowedOrigins,
        requireCsrfToken: false, // Pre-auth endpoint still requires trusted Origin
      });
      if (!originCheck.ok) {
        return { status: 403, headers: { 'X-Request-Id': requestId }, body: { error: { code: originCheck.code, message: originCheck.message, requestId } } };
      }

      const identifier = String(req.body?.identifier ?? '').trim();
      const deviceId = String(req.body?.deviceId ?? getHeader(req.headers, 'x-device-id') ?? '').trim();
      const ip = String(req.ip ?? getHeader(req.headers, 'x-forwarded-for') ?? 'unknown');

      if (!identifier || !deviceId) {
        return {
          status: 400,
          headers: { 'X-Request-Id': requestId },
          body: { error: { code: 'VALIDATION_ERROR', message: 'المعرّف ومعرّف الجهاز مطلوبان', requestId } },
        };
      }

      const res = await authService.requestOtp({ identifier, ip, deviceId, requestId, now });
      if (!res.ok) {
        return {
          status: res.status,
          headers: { 'X-Request-Id': requestId, ...(res.retryAfterSeconds ? { 'Retry-After': String(res.retryAfterSeconds) } : {}) },
          body: { error: { code: res.code, message: res.message, requestId } },
        };
      }

      return {
        status: 200,
        headers: { 'X-Request-Id': requestId },
        body: { challengeId: res.challengeId, expiresAt: res.expiresAt, requestId },
      };
    },

    async postAuthOtpVerify(req, now = new Date()) {
      const requestId = getHeader(req.headers, 'x-request-id') || randomUUID();
      const originCheck = verifyCsrfAndOrigin({
        method: 'POST',
        headers: req.headers,
        allowedOrigins,
        requireCsrfToken: false,
      });
      if (!originCheck.ok) {
        return { status: 403, headers: { 'X-Request-Id': requestId }, body: { error: { code: originCheck.code, message: originCheck.message, requestId } } };
      }

      const identifier = String(req.body?.identifier ?? '').trim();
      const code = String(req.body?.code ?? '').trim();
      const deviceId = String(req.body?.deviceId ?? getHeader(req.headers, 'x-device-id') ?? '').trim();
      const ip = String(req.ip ?? getHeader(req.headers, 'x-forwarded-for') ?? 'unknown');

      if (!identifier || !code || !deviceId) {
        return {
          status: 400,
          headers: { 'X-Request-Id': requestId },
          body: { error: { code: 'VALIDATION_ERROR', message: 'بيانات التحقق ناقصة', requestId } },
        };
      }

      const res = await authService.verifyOtpAndIssueSession({
        identifier,
        code,
        ip,
        deviceId,
        mfaVerified: req.body?.mfaVerified === true,
        mfaRecoveryCode: req.body?.mfaRecoveryCode ?? null,
        requestId,
        now,
      });

      if (!res.ok) {
        return {
          status: res.status,
          headers: { 'X-Request-Id': requestId, ...(res.retryAfterSeconds ? { 'Retry-After': String(res.retryAfterSeconds) } : {}) },
          body: { error: { code: res.code, message: res.message, requestId } },
        };
      }

      // Notice: session token is ONLY in Set-Cookie (HttpOnly), NEVER in JSON response body!
      return {
        status: 200,
        headers: { 'X-Request-Id': requestId, 'Set-Cookie': res.setCookies },
        body: {
          user: res.user,
          activeOrganizationId: res.activeOrganizationId,
          csrfToken: res.csrfToken,
          requestId,
        },
      };
    },

    async postAuthLogout(req, now = new Date()) {
      const guard = await guardProtectedRequest({
        req: { ...req, method: 'POST' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.PROPERTIES_VIEW, // Any authenticated active member can log out
        now,
      });
      if (!guard.ok) return guard;

      const out = await authService.logoutSession({ session: guard.session, requestId: guard.requestId, now });
      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId, 'Set-Cookie': out.setCookies },
        body: { loggedOut: true, requestId: guard.requestId },
      };
    },

    async postAuthRotateSession(req, now = new Date()) {
      const guard = await guardProtectedRequest({
        req: { ...req, method: 'POST' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.PROPERTIES_VIEW,
        now,
      });
      if (!guard.ok) return guard;

      const rotated = await authService.rotateSession({
        currentSession: guard.session,
        reason: 'explicit_rotation',
        requestId: guard.requestId,
        now,
      });
      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId, 'Set-Cookie': rotated.setCookies },
        body: { rotated: true, csrfToken: rotated.csrfToken, requestId: guard.requestId },
      };
    },

    async getMemberships(req, now = new Date()) {
      const guard = await guardProtectedRequest({
        req: { ...req, method: 'GET' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.USERS_INVITE,
        now,
      });
      if (!guard.ok) return guard;

      // Always scoped strictly to verifiedContext.organizationId (never client input)
      const memberships = await repo.listMembershipsByOrg(guard.verifiedContext.organizationId);
      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId },
        body: { organizationId: guard.verifiedContext.organizationId, memberships, requestId: guard.requestId },
      };
    },

    async postSuspendMembership(req, now = new Date()) {
      const targetMembershipId = req.body?.membershipId;
      const reason = String(req.body?.reason ?? '').trim();
      const target = targetMembershipId ? await repo.findMembershipById(targetMembershipId) : null;

      const guard = await guardProtectedRequest({
        req: { ...req, method: 'POST' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.USERS_SUSPEND,
        resource: target ? { organizationId: target.organizationId } : undefined,
        now,
      });
      if (!guard.ok) return guard;

      if (!target || target.organizationId !== guard.verifiedContext.organizationId) {
        // Unified non-leaking 404 (never reveals existence in another tenant)
        return {
          status: 404,
          headers: { 'X-Request-Id': guard.requestId },
          body: { error: { code: 'NOT_FOUND', message: 'العضوية غير موجودة', requestId: guard.requestId } },
        };
      }

      if (reason.length < 3) {
        return {
          status: 400,
          headers: { 'X-Request-Id': guard.requestId },
          body: { error: { code: 'REASON_REQUIRED', message: 'يجب ذكر سبب تعليق العضوية', requestId: guard.requestId } },
        };
      }

      await repo.updateMembershipStatus(target.id, guard.verifiedContext.organizationId, 'suspended', now);
      const rev = await authService.revokeSessionsForSuspendedMembership({
        userId: target.userId,
        organizationId: guard.verifiedContext.organizationId,
        reason,
        requestId: guard.requestId,
        now,
      });

      await repo.appendAuditLog({
        organizationId: guard.verifiedContext.organizationId,
        actorUserId: guard.verifiedContext.userId,
        action: 'membership.suspended',
        entityType: 'membership',
        entityId: target.id,
        before: { status: target.status },
        after: { status: 'suspended', revokedSessions: rev.revokedCount },
        reason,
        requestId: guard.requestId,
        deviceId: guard.session.deviceId,
        ipHash: null,
        createdAt: now,
      });

      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId },
        body: { suspended: true, membershipId: target.id, revokedSessions: rev.revokedCount, requestId: guard.requestId },
      };
    },

    async getRoles(req, now = new Date()) {
      const guard = await guardProtectedRequest({
        req: { ...req, method: 'GET' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.ROLES_MANAGE,
        now,
      });
      if (!guard.ok) return guard;

      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId },
        body: {
          organizationId: guard.verifiedContext.organizationId,
          systemRoles: Object.values(SYSTEM_ROLES),
          requestId: guard.requestId,
        },
      };
    },

    async postAssignRole(req, now = new Date()) {
      const targetMembershipId = req.body?.membershipId;
      const roleKey = String(req.body?.roleKey ?? '').trim();
      const target = targetMembershipId ? await repo.findMembershipById(targetMembershipId) : null;

      const guard = await guardProtectedRequest({
        req: { ...req, method: 'POST' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.ROLES_MANAGE,
        resource: target ? { organizationId: target.organizationId } : undefined,
        now,
      });
      if (!guard.ok) return guard;

      if (!target || target.organizationId !== guard.verifiedContext.organizationId) {
        return {
          status: 404,
          headers: { 'X-Request-Id': guard.requestId },
          body: { error: { code: 'NOT_FOUND', message: 'العضوية غير موجودة', requestId: guard.requestId } },
        };
      }

      if (!Object.values(SYSTEM_ROLES).includes(roleKey) || roleKey === SYSTEM_ROLES.PLATFORM_ADMIN) {
        return {
          status: 400,
          headers: { 'X-Request-Id': guard.requestId },
          body: { error: { code: 'INVALID_ROLE', message: 'الدور المطلوب غير مسموح بتعيينه ضمن المكتب', requestId: guard.requestId } },
        };
      }

      await repo.assignRoleToMembership(target.id, guard.verifiedContext.organizationId, roleKey);

      // Rotate actor session & revoke target sessions to enforce privilege change immediately
      const rotated = await authService.rotateSession({
        currentSession: guard.session,
        reason: `role_assigned:${roleKey}`,
        requestId: guard.requestId,
        now,
      });

      await repo.appendAuditLog({
        organizationId: guard.verifiedContext.organizationId,
        actorUserId: guard.verifiedContext.userId,
        action: 'role.assigned',
        entityType: 'membership',
        entityId: target.id,
        before: null,
        after: { roleKey },
        reason: String(req.body?.reason ?? 'role_update'),
        requestId: guard.requestId,
        deviceId: guard.session.deviceId,
        ipHash: null,
        createdAt: now,
      });

      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId, 'Set-Cookie': rotated.setCookies },
        body: {
          assigned: true,
          membershipId: target.id,
          roleKey,
          csrfToken: rotated.csrfToken,
          requestId: guard.requestId,
        },
      };
    },

    async getPermissions(req, now = new Date()) {
      const guard = await guardProtectedRequest({
        req: { ...req, method: 'GET' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission: PERMISSIONS.ROLES_MANAGE,
        now,
      });
      if (!guard.ok) return guard;

      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId },
        body: {
          permissions: ALL_PERMISSION_KEYS,
          requestId: guard.requestId,
        },
      };
    },
  };
}
