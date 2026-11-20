/**
 * CSRF & Origin Enforcement — منصة عقار 2.0 (OWASP ASVS L2)
 * Protects all state-changing API endpoints (POST, PUT, PATCH, DELETE) using:
 * 1. Strict Origin allowlist verification (fail-closed).
 * 2. Double-submit cookie + X-CSRF-Token header + server session csrfTokenHash verification.
 */

import { CSRF_COOKIE_NAME, parseCookieHeader } from './cookies.mjs';
import { verifyHashedSecret } from './crypto.mjs';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function verifyCsrfAndOrigin({
  method,
  headers,
  allowedOrigins,
  expectedCsrfTokenHash = null,
  pepper = null,
  requireCsrfToken = true,
}) {
  const upperMethod = String(method ?? 'GET').toUpperCase();
  if (SAFE_METHODS.has(upperMethod)) {
    return { ok: true };
  }

  // 1. Strict Origin check (fail-closed for state-changing requests)
  const origin = getHeader(headers, 'origin');
  if (!origin) {
    return {
      ok: false,
      code: 'CSRF_MISSING_ORIGIN',
      message: 'رفض الطلب: ترويسة Origin مفقودة في عملية تعديل',
    };
  }

  const allowSet = new Set(Array.isArray(allowedOrigins) ? allowedOrigins : []);
  if (!allowSet.has(origin)) {
    return {
      ok: false,
      code: 'CSRF_UNTRUSTED_ORIGIN',
      message: 'رفض الطلب: مصدر الطلب (Origin) غير موثوق',
    };
  }

  if (!requireCsrfToken) {
    return { ok: true };
  }

  // 2. Double-submit + Server Session CSRF hash verification
  const headerToken = getHeader(headers, 'x-csrf-token');
  const cookies = parseCookieHeader(getHeader(headers, 'cookie'));
  const cookieToken = cookies[CSRF_COOKIE_NAME];

  if (!headerToken || !cookieToken || headerToken !== cookieToken) {
    return {
      ok: false,
      code: 'CSRF_TOKEN_MISMATCH',
      message: 'رفض الطلب: رمز الحماية CSRF مفقود أو غير متطابق',
    };
  }

  if (expectedCsrfTokenHash && pepper) {
    const matchesSession = verifyHashedSecret(headerToken, expectedCsrfTokenHash, pepper, 'csrf');
    if (!matchesSession) {
      return {
        ok: false,
        code: 'CSRF_SESSION_BINDING_FAILED',
        message: 'رفض الطلب: رمز CSRF لا يطابق الجلسة النشطة',
      };
    }
  }

  return { ok: true };
}

export function getHeader(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === 'function') {
    return headers.get(name);
  }
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) {
      return Array.isArray(v) ? v[0] : v;
    }
  }
  return null;
}
