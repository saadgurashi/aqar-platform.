/**
 * Private Storage Isolation & Short-Lived Signed URL Service — منصة عقار 2.0 (Section 3.9 & Blueprint 6)
 *
 * Security invariants:
 * - Private documents and private media NEVER use permanent public URLs.
 * - Storage keys are opaque, unpredictable, and tenant-prefixed; path traversal (`..`, leading `/`, URLs) is rejected.
 * - Signing keys live strictly on the server (never exposed to client code).
 * - Signed URLs have a strict short TTL (default 120s, hard cap 300s) and bind orgId + fileId + storageKey + actorUserId + exp.
 * - Issuing a signed URL ALWAYS requires prior server-side RBAC + tenant ownership verification.
 */

import { randomBytes, randomUUID } from 'node:crypto';
import { hashSecret, verifyHashedSecret } from '../auth/crypto.mjs';

const MAX_SIGNED_URL_TTL_SECONDS = 300; // 5 minutes hard ceiling
const DEFAULT_SIGNED_URL_TTL_SECONDS = 120; // 2 minutes default
const SAFE_STORAGE_KEY_REGEX = /^tenants\/[0-9a-f-]{36}\/(documents|private-media|public-media)\/[0-9a-f-]{36}-[0-9a-f]{32}\.[a-z0-9]{2,8}$/i;

export function generateOpaqueStorageKey({ organizationId, category = 'documents', extension = 'pdf' }) {
  const cleanExt = String(extension).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (!cleanExt || cleanExt.length < 2 || cleanExt.length > 8) {
    throw new Error('INVALID_FILE_EXTENSION');
  }
  if (!['documents', 'private-media', 'public-media'].includes(category)) {
    throw new Error('INVALID_STORAGE_CATEGORY');
  }
  const rand = randomBytes(16).toString('hex');
  const key = `tenants/${organizationId}/${category}/${randomUUID()}-${rand}.${cleanExt}`;
  assertSafeStorageKey(key);
  return key;
}

export function assertSafeStorageKey(storageKey) {
  if (typeof storageKey !== 'string') {
    throw new Error('INVALID_STORAGE_KEY');
  }
  if (
    storageKey.includes('..') ||
    storageKey.includes('\\') ||
    storageKey.includes('\0') ||
    storageKey.startsWith('/') ||
    /^https?:\/\//i.test(storageKey) ||
    !SAFE_STORAGE_KEY_REGEX.test(storageKey)
  ) {
    throw new Error('UNSAFE_STORAGE_KEY: المسار غير آمن أو يخالف نمط المفاتيح المعزولة');
  }
}

export class PrivateStorageService {
  /**
   * @param {Object} deps
   * @param {string} deps.signingSecret Server-only HMAC signing secret (>= 32 chars recommended)
   * @param {string} [deps.baseDownloadPath='/api/v1/storage/download']
   */
  constructor({ signingSecret, baseDownloadPath = '/api/v1/storage/download' }) {
    if (!signingSecret || signingSecret.length < 16) {
      throw new Error('SECURITY_CONFIG_ERROR: signingSecret must be at least 16 characters');
    }
    this.signingSecret = signingSecret;
    this.baseDownloadPath = baseDownloadPath;
  }

  /**
   * Issues a short-lived signed download URL ONLY after the caller has verified RBAC & tenant ownership.
   */
  issueSignedDownloadUrl({
    verifiedOrganizationId,
    actorUserId,
    fileRecord,
    ttlSeconds = DEFAULT_SIGNED_URL_TTL_SECONDS,
    now = new Date(),
  }) {
    if (!verifiedOrganizationId || !actorUserId || !fileRecord) {
      throw new Error('FAIL_CLOSED: Missing verified context or file record');
    }

    // Defense-in-depth tenant isolation check
    if (fileRecord.organizationId !== verifiedOrganizationId) {
      throw new Error('CROSS_TENANT_STORAGE_DENIED');
    }

    const storageKey = fileRecord.privateStorageKey ?? fileRecord.storageKey;
    assertSafeStorageKey(storageKey);

    if (!storageKey.startsWith(`tenants/${verifiedOrganizationId}/`)) {
      throw new Error('STORAGE_KEY_TENANT_PREFIX_MISMATCH');
    }

    const boundedTtl = Math.min(Math.max(10, Math.floor(ttlSeconds)), MAX_SIGNED_URL_TTL_SECONDS);
    const exp = Math.floor(now.getTime() / 1000) + boundedTtl;

    const canonicalPayload = `${verifiedOrganizationId}|${fileRecord.id}|${storageKey}|${actorUserId}|${exp}`;
    const sig = hashSecret(canonicalPayload, this.signingSecret, 'signed-url-v1');

    const params = new URLSearchParams({
      org: verifiedOrganizationId,
      fid: fileRecord.id,
      key: storageKey,
      uid: actorUserId,
      exp: String(exp),
      sig,
    });

    return {
      url: `${this.baseDownloadPath}?${params.toString()}`,
      expiresAt: new Date(exp * 1000).toISOString(),
      ttlSeconds: boundedTtl,
    };
  }

  /**
   * Verifies a signed download URL before streaming bytes from private S3-compatible storage.
   */
  verifySignedDownloadUrl(queryParams, now = new Date()) {
    const org = queryParams?.org;
    const fid = queryParams?.fid;
    const key = queryParams?.key;
    const uid = queryParams?.uid;
    const expRaw = queryParams?.exp;
    const sig = queryParams?.sig;

    if (!org || !fid || !key || !uid || !expRaw || !sig) {
      return { ok: false, code: 'SIGNED_URL_MALFORMED', message: 'رابط التنزيل غير مكتمل' };
    }

    try {
      assertSafeStorageKey(key);
    } catch {
      return { ok: false, code: 'UNSAFE_STORAGE_KEY', message: 'مسار الملف غير صالح' };
    }

    if (!key.startsWith(`tenants/${org}/`)) {
      return { ok: false, code: 'TENANT_PREFIX_MISMATCH', message: 'رفض الوصول: تضارب معرّف المؤسسة في المسار' };
    }

    const exp = Number(expRaw);
    const nowSec = Math.floor(now.getTime() / 1000);
    if (!Number.isFinite(exp) || exp <= nowSec) {
      return { ok: false, code: 'SIGNED_URL_EXPIRED', message: 'انتهت صلاحية رابط التنزيل المؤقت' };
    }

    const canonicalPayload = `${org}|${fid}|${key}|${uid}|${exp}`;
    const valid = verifyHashedSecret(canonicalPayload, sig, this.signingSecret, 'signed-url-v1');
    if (!valid) {
      return { ok: false, code: 'SIGNED_URL_INVALID_SIGNATURE', message: 'توقيع الرابط غير صالح أو تم العبث به' };
    }

    return {
      ok: true,
      organizationId: org,
      fileId: fid,
      storageKey: key,
      actorUserId: uid,
      expiresAt: new Date(exp * 1000).toISOString(),
    };
  }
}
