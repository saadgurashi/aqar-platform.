/**
 * Audit Log Payload Sanitizer — منصة عقار 2.0 (Section 3.8 & 3.10)
 * Redacts secrets, OTPs, tokens, passwords, and recovery codes before persisting audit logs.
 */

const SENSITIVE_KEY_PATTERN = /(password|passwd|secret|token|otp|recovery_code|authorization|cookie|private_key|api_key)/i;

export function sanitizeAuditPayload(value) {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAuditPayload(item));
  }
  if (typeof value === 'object') {
    const clean = {};
    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        clean[key] = '[REDACTED]';
      } else {
        clean[key] = sanitizeAuditPayload(val);
      }
    }
    return clean;
  }
  return value;
}
