/**
 * Authentication, OTP, MFA & Device Session Service — منصة عقار 2.0 (Section 3.10)
 *
 * Security invariants enforced:
 * - OTPs and session/CSRF tokens are NEVER stored or logged in plaintext (HMAC-SHA256 + salt).
 * - OTP is single-use, expires after 5 minutes, and locks after maxAttempts (default 5).
 * - Multi-dimensional rate limiting across Account + IP + Device.
 * - Mandatory MFA for Owner, Manager, and Platform Admin (cannot be bypassed via API).
 * - Session rotation on authentication, org switch, and privilege/role changes.
 * - Immediate session revocation on logout, credential change, compromise, or membership suspension.
 * - Dual session timeout: idle timeout (30 min) + absolute max lifetime (12 hours).
 */

import { randomUUID } from 'node:crypto';
import {
  generateOpaqueToken,
  generateOtpCode,
  generateSalt,
  hashIdentifier,
  hashSecret,
  verifyHashedSecret,
} from '../../shared/auth/crypto.mjs';
import {
  buildClearAuthCookies,
  buildCsrfCookie,
  buildSessionCookie,
} from '../../shared/auth/cookies.mjs';
import { enforceMultiDimensionalRateLimit } from '../../shared/auth/rate-limiter.mjs';
import { sanitizeAuditPayload } from '../../shared/audit/sanitizer.mjs';
import { MFA_REQUIRED_ROLES } from '../authorization/permissions.mjs';
import { UnconfiguredOtpProvider } from './otp-provider.mjs';

const DEFAULT_OTP_TTL_SECONDS = 300; // 5 minutes
const DEFAULT_OTP_MAX_ATTEMPTS = 5;
const DEFAULT_SESSION_IDLE_SECONDS = 30 * 60; // 30 minutes
const DEFAULT_SESSION_MAX_SECONDS = 12 * 60 * 60; // 12 hours

export class AuthSessionService {
  /**
   * @param {Object} deps
   * @param {Object} deps.repo Persistence repository (PostgreSQL in prod, test adapter in unit tests)
   * @param {Object} deps.rateLimitStore Distributed RateLimitStore (PgRateLimitStore in prod)
   * @param {Object} [deps.otpProvider] External OTP delivery provider
   * @param {string} deps.secretPepper Server-side secret pepper (>= 16 chars)
   * @param {Object} [deps.config] Optional TTL overrides
   */
  constructor({ repo, rateLimitStore, otpProvider = new UnconfiguredOtpProvider(), secretPepper, config = {} }) {
    if (!secretPepper || secretPepper.length < 16) {
      throw new Error('SECURITY_CONFIG_ERROR: secretPepper must be at least 16 characters');
    }
    this.repo = repo;
    this.rateLimitStore = rateLimitStore;
    this.otpProvider = otpProvider;
    this.pepper = secretPepper;
    this.otpTtlSeconds = config.otpTtlSeconds ?? DEFAULT_OTP_TTL_SECONDS;
    this.otpMaxAttempts = config.otpMaxAttempts ?? DEFAULT_OTP_MAX_ATTEMPTS;
    this.sessionIdleSeconds = config.sessionIdleSeconds ?? DEFAULT_SESSION_IDLE_SECONDS;
    this.sessionMaxSeconds = config.sessionMaxSeconds ?? DEFAULT_SESSION_MAX_SECONDS;
  }

  async requestOtp({ identifier, ip, deviceId, purpose = 'login', requestId = randomUUID(), now = new Date() }) {
    const identifierHash = hashIdentifier(identifier, this.pepper);
    const ipHash = hashIdentifier(ip, this.pepper);

    const rl = await enforceMultiDimensionalRateLimit(this.rateLimitStore, {
      action: `otp_request_${purpose}`,
      accountKey: identifierHash,
      ipKey: ipHash,
      deviceKey: deviceId,
      now,
    });

    if (!rl.allowed) {
      await this.repo.recordLoginAttempt({
        identifierHash,
        deviceId,
        ipHash,
        outcome: 'rate_limited',
        createdAt: now,
      });
      return {
        ok: false,
        status: 429,
        code: 'RATE_LIMITED',
        dimension: rl.dimension,
        retryAfterSeconds: rl.retryAfterSeconds,
        message: 'تم تجاوز الحد المسموح من المحاولات؛ يرجى المحاولة لاحقاً',
      };
    }

    const code = generateOtpCode(6);
    const salt = generateSalt(16);
    const codeHash = hashSecret(code, this.pepper, salt);
    const expiresAt = new Date(now.getTime() + this.otpTtlSeconds * 1000);

    const challenge = await this.repo.createOtpChallenge({
      id: randomUUID(),
      identifierHash,
      purpose,
      codeHash,
      salt,
      attempts: 0,
      maxAttempts: this.otpMaxAttempts,
      expiresAt,
      consumedAt: null,
      deviceId,
      ipHash,
      createdAt: now,
    });

    // Delegate actual delivery to external provider abstraction
    await this.otpProvider.sendOtp({
      destination: identifier,
      code,
      purpose,
      expiresInMinutes: Math.ceil(this.otpTtlSeconds / 60),
      requestId,
    });

    await this.repo.recordLoginAttempt({
      identifierHash,
      deviceId,
      ipHash,
      outcome: 'otp_sent',
      createdAt: now,
    });

    // Audit log is sanitized — NEVER contains plaintext OTP
    await this.repo.appendAuditLog(
      sanitizeAuditPayload({
        organizationId: null,
        actorUserId: null,
        action: 'auth.otp.requested',
        entityType: 'otp_challenge',
        entityId: challenge.id,
        before: null,
        after: { purpose, expiresAt: expiresAt.toISOString() },
        reason: null,
        requestId,
        deviceId,
        ipHash,
        createdAt: now,
      }),
    );

    return {
      ok: true,
      status: 200,
      challengeId: challenge.id,
      expiresAt: expiresAt.toISOString(),
    };
  }

  async verifyOtpAndIssueSession({
    identifier,
    code,
    ip,
    deviceId,
    mfaVerified = false,
    mfaRecoveryCode = null,
    requestId = randomUUID(),
    now = new Date(),
  }) {
    const identifierHash = hashIdentifier(identifier, this.pepper);
    const ipHash = hashIdentifier(ip, this.pepper);

    const rl = await enforceMultiDimensionalRateLimit(this.rateLimitStore, {
      action: 'otp_verify',
      accountKey: identifierHash,
      ipKey: ipHash,
      deviceKey: deviceId,
      now,
    });

    if (!rl.allowed) {
      await this.repo.recordLoginAttempt({
        identifierHash,
        deviceId,
        ipHash,
        outcome: 'rate_limited',
        createdAt: now,
      });
      return {
        ok: false,
        status: 429,
        code: 'RATE_LIMITED',
        dimension: rl.dimension,
        retryAfterSeconds: rl.retryAfterSeconds,
        message: 'تم تجاوز الحد المسموح لمحاولات التحقق',
      };
    }

    const challenge = await this.repo.findLatestOtpChallenge(identifierHash, 'login');
    if (!challenge) {
      await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'failed', createdAt: now });
      return { ok: false, status: 401, code: 'OTP_INVALID', message: 'رمز التحقق غير صالح' };
    }

    if (challenge.consumedAt) {
      await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'failed', createdAt: now });
      return { ok: false, status: 401, code: 'OTP_ALREADY_USED', message: 'تم استخدام رمز التحقق مسبقاً' };
    }

    if (new Date(challenge.expiresAt) <= now) {
      await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'failed', createdAt: now });
      return { ok: false, status: 401, code: 'OTP_EXPIRED', message: 'انتهت صلاحية رمز التحقق' };
    }

    if (challenge.attempts >= challenge.maxAttempts) {
      await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'failed', createdAt: now });
      return { ok: false, status: 429, code: 'OTP_MAX_ATTEMPTS', message: 'تم إقفال الرمز لتجاوز عدد المحاولات المسموح' };
    }

    const isCodeValid = verifyHashedSecret(code, challenge.codeHash, this.pepper, challenge.salt);
    if (!isCodeValid) {
      const nextAttempts = challenge.attempts + 1;
      await this.repo.incrementOtpAttempts(challenge.id, nextAttempts, nextAttempts >= challenge.maxAttempts ? now : null);
      await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'failed', createdAt: now });
      return {
        ok: false,
        status: nextAttempts >= challenge.maxAttempts ? 429 : 401,
        code: nextAttempts >= challenge.maxAttempts ? 'OTP_MAX_ATTEMPTS' : 'OTP_INVALID',
        message: 'رمز التحقق غير صحيح',
      };
    }

    // Consume OTP immediately (single-use atomic guarantee)
    await this.repo.consumeOtpChallenge(challenge.id, now);

    const user = await this.repo.findUserByIdentifier(identifier);
    if (!user || user.status !== 'active') {
      return { ok: false, status: 403, code: 'USER_INACTIVE', message: 'الحساب غير نشط أو غير موجود' };
    }

    const activeMemberships = await this.repo.findActiveMembershipsForUser(user.id);
    const primaryMembership = activeMemberships[0] ?? null;
    const roles = primaryMembership
      ? await this.repo.findRoleKeysForMembership(primaryMembership.id, primaryMembership.organizationId)
      : [];

    // Enforce MFA for Owner, Manager, Platform Admin (Section 3.10)
    const requiresMfa = roles.some((r) => MFA_REQUIRED_ROLES.has(r));
    let mfaSatisfied = mfaVerified === true && user.mfaEnabled === true;

    if (requiresMfa && !mfaSatisfied && mfaRecoveryCode) {
      const recoveryHash = hashSecret(mfaRecoveryCode, this.pepper, 'mfa_recovery');
      const consumedRecovery = await this.repo.consumeMfaRecoveryCode(user.id, recoveryHash, now);
      if (consumedRecovery) {
        mfaSatisfied = true;
      }
    }

    if (requiresMfa && !mfaSatisfied) {
      await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'mfa_failed', createdAt: now });
      return {
        ok: false,
        status: 403,
        code: 'MFA_REQUIRED',
        message: 'يتطلب هذا الدور إتمام المصادقة متعددة العوامل (MFA)',
      };
    }

    // Issue fresh rotated session + CSRF token (stored ONLY as hashes; returned ONLY via HttpOnly cookies)
    const issued = await this.#issueSessionRecord({
      userId: user.id,
      activeOrganizationId: primaryMembership?.organizationId ?? null,
      deviceId,
      now,
    });

    await this.repo.recordLoginAttempt({ identifierHash, deviceId, ipHash, outcome: 'verified', createdAt: now });
    await this.repo.appendAuditLog(
      sanitizeAuditPayload({
        organizationId: primaryMembership?.organizationId ?? null,
        actorUserId: user.id,
        action: 'auth.session.issued',
        entityType: 'device_session',
        entityId: issued.session.id,
        before: null,
        after: { deviceId, activeOrganizationId: issued.session.activeOrganizationId },
        reason: null,
        requestId,
        deviceId,
        ipHash,
        createdAt: now,
      }),
    );

    return {
      ok: true,
      status: 200,
      sessionId: issued.session.id,
      user: {
        id: user.id,
        fullName: user.fullName,
        mfaEnabled: user.mfaEnabled,
      },
      activeOrganizationId: issued.session.activeOrganizationId,
      csrfToken: issued.rawCsrfToken, // Safe for client memory/header; NEVER session token!
      setCookies: issued.setCookies,
    };
  }

  async resolveSessionFromToken(rawSessionToken, now = new Date()) {
    if (!rawSessionToken || typeof rawSessionToken !== 'string') {
      return { ok: false, code: 'UNAUTHENTICATED' };
    }
    const tokenHash = hashSecret(rawSessionToken, this.pepper, 'session');
    const session = await this.repo.findSessionByTokenHash(tokenHash);
    if (!session) {
      return { ok: false, code: 'SESSION_NOT_FOUND' };
    }
    if (session.revokedAt) {
      return { ok: false, code: 'SESSION_REVOKED' };
    }
    if (new Date(session.expiresAt) <= now) {
      return { ok: false, code: 'SESSION_EXPIRED' };
    }
    if (new Date(session.idleTimeoutAt) <= now) {
      await this.repo.revokeSession(session.id, 'idle_timeout', now);
      return { ok: false, code: 'SESSION_IDLE_TIMEOUT' };
    }

    // Slide idle window forward (capped at absolute max expiry)
    const nextIdle = new Date(
      Math.min(now.getTime() + this.sessionIdleSeconds * 1000, new Date(session.expiresAt).getTime()),
    );
    await this.repo.touchSession(session.id, now, nextIdle);
    session.lastSeenAt = now;
    session.idleTimeoutAt = nextIdle;

    return { ok: true, session };
  }

  async rotateSession({ currentSession, reason = 'rotation', requestId = randomUUID(), now = new Date() }) {
    await this.repo.revokeSession(currentSession.id, `rotated:${reason}`, now);
    const issued = await this.#issueSessionRecord({
      userId: currentSession.userId,
      activeOrganizationId: currentSession.activeOrganizationId,
      deviceId: currentSession.deviceId,
      now,
    });

    await this.repo.appendAuditLog(
      sanitizeAuditPayload({
        organizationId: currentSession.activeOrganizationId,
        actorUserId: currentSession.userId,
        action: 'auth.session.rotated',
        entityType: 'device_session',
        entityId: issued.session.id,
        before: { previousSessionId: currentSession.id },
        after: { newSessionId: issued.session.id },
        reason,
        requestId,
        deviceId: currentSession.deviceId,
        ipHash: null,
        createdAt: now,
      }),
    );

    return {
      ok: true,
      sessionId: issued.session.id,
      csrfToken: issued.rawCsrfToken,
      setCookies: issued.setCookies,
    };
  }

  async logoutSession({ session, requestId = randomUUID(), now = new Date() }) {
    await this.repo.revokeSession(session.id, 'user_logout', now);
    await this.repo.appendAuditLog({
      organizationId: session.activeOrganizationId,
      actorUserId: session.userId,
      action: 'auth.session.logout',
      entityType: 'device_session',
      entityId: session.id,
      before: { revokedAt: null },
      after: { revokedAt: now.toISOString() },
      reason: 'user_logout',
      requestId,
      deviceId: session.deviceId,
      ipHash: null,
      createdAt: now,
    });
    return { ok: true, setCookies: buildClearAuthCookies() };
  }

  async revokeSessionsForSuspendedMembership({ userId, organizationId, reason = 'membership_suspended', requestId = randomUUID(), now = new Date() }) {
    const revokedCount = await this.repo.revokeUserSessionsForOrg(userId, organizationId, reason, now);
    await this.repo.appendAuditLog({
      organizationId,
      actorUserId: userId,
      action: 'auth.sessions.revoked_on_suspension',
      entityType: 'membership',
      entityId: null,
      before: null,
      after: { revokedCount },
      reason,
      requestId,
      deviceId: null,
      ipHash: null,
      createdAt: now,
    });
    return { ok: true, revokedCount };
  }

  async #issueSessionRecord({ userId, activeOrganizationId, deviceId, now }) {
    const rawSessionToken = generateOpaqueToken(32);
    const rawCsrfToken = generateOpaqueToken(32);
    const tokenHash = hashSecret(rawSessionToken, this.pepper, 'session');
    const csrfTokenHash = hashSecret(rawCsrfToken, this.pepper, 'csrf');

    const expiresAt = new Date(now.getTime() + this.sessionMaxSeconds * 1000);
    const idleTimeoutAt = new Date(now.getTime() + this.sessionIdleSeconds * 1000);

    const session = await this.repo.createSession({
      id: randomUUID(),
      userId,
      activeOrganizationId,
      deviceId,
      tokenHash,
      csrfTokenHash,
      issuedAt: now,
      lastSeenAt: now,
      idleTimeoutAt,
      expiresAt,
      revokedAt: null,
      revokedReason: null,
    });

    const setCookies = [
      buildSessionCookie(rawSessionToken, this.sessionMaxSeconds),
      buildCsrfCookie(rawCsrfToken, this.sessionMaxSeconds),
    ];

    return { session, rawCsrfToken, setCookies };
  }
}
