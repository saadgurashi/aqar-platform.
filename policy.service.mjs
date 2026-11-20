/**
 * Server-Side Authorization Policy Service — منصة عقار 2.0 (Section 3.4)
 *
 * Enforces the mandatory 6-step authorization sequence:
 * 1. Verify authenticated user & active non-expired, non-revoked session.
 * 2. Derive organization_id strictly from trusted session context (never trust client input)
 *    and verify an ACTIVE membership exists.
 * 3. Load effective roles & non-expired permission_overrides (deny takes precedence).
 * 4. Check action permission, ownership/scope (.own vs .any), MFA enforcement, and SoD rules.
 * 5. Return a verified tenant execution context ready for PostgreSQL RLS transaction binding.
 * 6. Emit sanitized audit/security event descriptors for denials & sensitive actions.
 */

import {
  MFA_REQUIRED_ROLES,
  PERMISSION_SET,
  PERMISSIONS,
  ROLE_PERMISSION_MATRIX,
  SOD_RESTRICTED_PERMISSIONS,
} from './permissions.mjs';

/**
 * @typedef {Object} AuthDecision
 * @property {boolean} allowed
 * @property {string} reasonCode
 * @property {string} message
 * @property {{ userId: string, organizationId: string, membershipId: string, roles: string[] } | null} verifiedContext
 * @property {{ severity: 'medium'|'high'|'critical', eventType: string, details: Record<string, unknown> } | null} securityEvent
 */

/**
 * Evaluates authorization fail-closed according to Section 3.4.
 *
 * @param {Object} input
 * @param {Object | null} input.session Trusted server-side session record
 * @param {Object | null} input.user Trusted user record
 * @param {Object | null} input.membership Trusted membership record for session.activeOrganizationId
 * @param {string[]} input.roles Assigned role keys for the membership
 * @param {Array<{ permissionKey: string, effect: 'allow'|'deny', expiresAt: string|Date }>} [input.overrides]
 * @param {string} input.requiredPermission Permission key to check
 * @param {string} [input.claimedOrganizationId] Optional client-supplied org ID (checked for spoofing!)
 * @param {Object} [input.resource] Optional resource attributes for ownership/scope/SoD checks
 * @param {string} [input.resource.organizationId] Resource's actual organization_id
 * @param {string} [input.resource.ownerUserId] Resource owner/assignee user_id (for .own checks)
 * @param {string} [input.resource.createdByUserId] Creator user_id (for SoD maker-checker checks)
 * @param {boolean} [input.orgRequiresPaymentSod=true] Organization SoD policy flag
 * @param {Date} [input.now] Reference UTC timestamp
 * @returns {AuthDecision}
 */
export function evaluateAuthorization(input) {
  const now = input.now instanceof Date ? input.now : new Date();

  // Step 1: Verify authenticated user & active session
  if (!input.session || !input.user) {
    return deny('UNAUTHENTICATED', 'الجلسة غير صالحة أو غير مصادق عليها', 'medium', 'auth.unauthenticated');
  }

  if (input.user.status !== 'active') {
    return deny('USER_INACTIVE', 'حساب المستخدم غير نشط', 'high', 'auth.inactive_user', {
      userId: input.user.id,
      status: input.user.status,
    });
  }

  if (input.session.revokedAt) {
    return deny('SESSION_REVOKED', 'تم إبطال الجلسة', 'high', 'auth.session_revoked', {
      sessionId: input.session.id,
    });
  }

  const sessionExpiresAt = new Date(input.session.expiresAt);
  if (Number.isNaN(sessionExpiresAt.getTime()) || sessionExpiresAt <= now) {
    return deny('SESSION_EXPIRED', 'انتهت صلاحية الجلسة', 'medium', 'auth.session_expired', {
      sessionId: input.session.id,
    });
  }

  // Step 2: Trusted organization_id & active membership (NEVER trust client-sent org ID)
  const trustedOrgId = input.session.activeOrganizationId;
  if (!trustedOrgId) {
    return deny('MISSING_TENANT_CONTEXT', 'لا يوجد مكتب نشط في الجلسة', 'high', 'tenant.missing_context');
  }

  if (input.claimedOrganizationId && input.claimedOrganizationId !== trustedOrgId) {
    return deny(
      'TENANT_CONTEXT_MISMATCH',
      'رفض الوصول: محاولة تمرير معرف مكتب مخالف للجلسة الموثوقة',
      'critical',
      'security.tenant_spoofing_attempt',
      {
        trustedOrgId,
        claimedOrganizationId: input.claimedOrganizationId,
        userId: input.user.id,
      },
    );
  }

  if (
    !input.membership ||
    input.membership.userId !== input.user.id ||
    input.membership.organizationId !== trustedOrgId ||
    input.membership.status !== 'active'
  ) {
    return deny(
      'MEMBERSHIP_INACTIVE',
      'لا توجد عضوية نشطة للمستخدم في هذا المكتب',
      'high',
      'auth.membership_denied',
      {
        trustedOrgId,
        userId: input.user.id,
        membershipStatus: input.membership?.status ?? 'none',
      },
    );
  }

  // Cross-tenant resource guard (IDOR prevention at application layer in addition to RLS)
  if (input.resource?.organizationId && input.resource.organizationId !== trustedOrgId) {
    return deny(
      'CROSS_TENANT_ACCESS_DENIED',
      'رفض الوصول إلى مورد تابع لمكتب آخر',
      'critical',
      'security.cross_tenant_idor_attempt',
      {
        trustedOrgId,
        resourceOrgId: input.resource.organizationId,
        userId: input.user.id,
      },
    );
  }

  // Validate permission key exists in registry
  if (!PERMISSION_SET.has(input.requiredPermission)) {
    return deny('UNKNOWN_PERMISSION', 'مفتاح الصلاحية غير معروف', 'high', 'rbac.unknown_permission', {
      requiredPermission: input.requiredPermission,
    });
  }

  // Step 3: Load effective roles, enforce MFA for privileged roles, evaluate overrides
  const roles = Array.isArray(input.roles) ? input.roles : [];
  const requiresMfa = roles.some((role) => MFA_REQUIRED_ROLES.has(role));
  if (requiresMfa && !input.user.mfaEnabled) {
    return deny(
      'MFA_REQUIRED',
      'يجب تفعيل المصادقة متعددة العوامل (MFA) لهذا الدور',
      'high',
      'auth.mfa_required',
      { userId: input.user.id, roles },
    );
  }

  const effectiveAllowed = new Set();
  for (const roleKey of roles) {
    const perms = ROLE_PERMISSION_MATRIX[roleKey];
    if (perms) {
      for (const p of perms) {
        effectiveAllowed.add(p);
      }
    }
  }

  const explicitDenies = new Set();
  const overrides = Array.isArray(input.overrides) ? input.overrides : [];
  for (const ov of overrides) {
    const exp = new Date(ov.expiresAt);
    if (Number.isNaN(exp.getTime()) || exp <= now) {
      continue; // Expired override MUST be ignored
    }
    if (ov.effect === 'deny') {
      explicitDenies.add(ov.permissionKey);
    } else if (ov.effect === 'allow' && PERMISSION_SET.has(ov.permissionKey)) {
      effectiveAllowed.add(ov.permissionKey);
    }
  }

  // Step 4: Check permission, ownership (.own vs .any), and Separation of Duties (SoD)
  const required = input.requiredPermission;

  if (explicitDenies.has(required)) {
    return deny('EXPLICIT_DENY_OVERRIDE', 'تم تقييد هذه الصلاحية باستثناء منع نشط', 'high', 'rbac.explicit_deny', {
      userId: input.user.id,
      requiredPermission: required,
    });
  }

  // Special handling for properties.update.own vs properties.update.any
  if (required === PERMISSIONS.PROPERTIES_UPDATE_OWN) {
    const canAny = effectiveAllowed.has(PERMISSIONS.PROPERTIES_UPDATE_ANY) && !explicitDenies.has(PERMISSIONS.PROPERTIES_UPDATE_ANY);
    const canOwn = effectiveAllowed.has(PERMISSIONS.PROPERTIES_UPDATE_OWN);

    if (!canAny && !canOwn) {
      return deny('FORBIDDEN', 'لا تملك صلاحية تعديل العقارات', 'medium', 'rbac.permission_denied', {
        userId: input.user.id,
        requiredPermission: required,
      });
    }

    if (!canAny && canOwn) {
      if (!input.resource?.ownerUserId || input.resource.ownerUserId !== input.user.id) {
        return deny(
          'OWNERSHIP_REQUIRED',
          'صلاحيتك تقتصر على تعديل العقارات المسندة إليك فقط',
          'high',
          'rbac.ownership_violation',
          {
            userId: input.user.id,
            resourceOwnerUserId: input.resource?.ownerUserId ?? null,
          },
        );
      }
    }
  } else if (!effectiveAllowed.has(required)) {
    return deny('FORBIDDEN', 'لا تملك الصلاحية المطلوبة لتنفيذ هذا الإجراء', 'high', 'rbac.permission_denied', {
      userId: input.user.id,
      roles,
      requiredPermission: required,
    });
  }

  // Separation of Duties (SoD): Maker cannot be Checker for payment confirmation / refund approval
  const requireSod = input.orgRequiresPaymentSod !== false;
  if (
    requireSod &&
    SOD_RESTRICTED_PERMISSIONS.has(required) &&
    input.resource?.createdByUserId &&
    input.resource.createdByUserId === input.user.id
  ) {
    return deny(
      'SOD_CONFLICT_OF_DUTIES',
      'تعارض واجبات: لا يجوز لمنشئ العملية المالية اعتمادها بنفسه',
      'high',
      'rbac.sod_violation',
      {
        userId: input.user.id,
        requiredPermission: required,
      },
    );
  }

  // Step 5: Verified tenant context ready for DB transaction + RLS
  return {
    allowed: true,
    reasonCode: 'ALLOWED',
    message: 'تم التحقق من الصلاحية وسياق المكتب',
    verifiedContext: {
      userId: input.user.id,
      organizationId: trustedOrgId,
      membershipId: input.membership.id,
      roles,
    },
    securityEvent: null,
  };
}

function deny(reasonCode, message, severity, eventType, details = {}) {
  return {
    allowed: false,
    reasonCode,
    message,
    verifiedContext: null,
    securityEvent: {
      severity,
      eventType,
      details,
    },
  };
}
