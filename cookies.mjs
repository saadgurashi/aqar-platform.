/**
 * Secure Auth Cookie Builder & Parser — منصة عقار 2.0 (Section 3.10 & OWASP ASVS L2)
 * Session tokens are ALWAYS stored in HttpOnly, Secure, SameSite=Lax cookies — NEVER localStorage.
 */

export const SESSION_COOKIE_NAME = '__Host-aqar_session';
export const CSRF_COOKIE_NAME = '__Host-aqar_csrf';

export function buildSessionCookie(token, maxAgeSeconds) {
  return [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ].join('; ');
}

export function buildCsrfCookie(csrfToken, maxAgeSeconds) {
  return [
    `${CSRF_COOKIE_NAME}=${encodeURIComponent(csrfToken)}`,
    'Path=/',
    'Secure',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ].join('; ');
}

export function buildClearAuthCookies() {
  return [
    `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `${CSRF_COOKIE_NAME}=; Path=/; Secure; SameSite=Strict; Max-Age=0`,
  ];
}

export function parseCookieHeader(cookieHeader) {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return cookies;
  }
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}
