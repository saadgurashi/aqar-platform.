/**
 * Cryptographic Helpers — منصة عقار 2.0 (Section 3.10)
 * Uses Node.js built-in crypto with constant-time comparison.
 * NEVER stores or returns plaintext secrets for persistence.
 */

import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

export function generateOtpCode(digits = 6) {
  const max = 10 ** digits;
  return String(randomInt(0, max)).padStart(digits, '0');
}

export function generateOpaqueToken(byteLength = 32) {
  return randomBytes(byteLength).toString('base64url');
}

export function generateSalt(byteLength = 16) {
  return randomBytes(byteLength).toString('hex');
}

export function hashSecret(secret, pepper, salt = '') {
  if (!pepper || typeof pepper !== 'string' || pepper.length < 16) {
    throw new Error('SECURITY_CONFIG_ERROR: Server secret pepper must be at least 16 characters');
  }
  return createHmac('sha256', pepper)
    .update(`${salt}:${secret}`)
    .digest('hex');
}

export function verifyHashedSecret(secret, expectedHash, pepper, salt = '') {
  if (typeof secret !== 'string' || typeof expectedHash !== 'string' || expectedHash.length === 0) {
    return false;
  }
  const actualHash = hashSecret(secret, pepper, salt);
  const a = Buffer.from(actualHash, 'hex');
  const b = Buffer.from(expectedHash, 'hex');
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

export function hashIdentifier(value, pepper) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return hashSecret(normalized, pepper, 'id');
}
