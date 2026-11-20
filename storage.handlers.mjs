/**
 * Private Storage API Handlers — منصة عقار 2.0 (Section 3.9 Storage Isolation)
 *
 * - POST /api/v1/storage/signed-url : Server-side auth + RBAC + tenant check -> short-lived signed URL
 * - GET  /api/v1/storage/download   : Verifies HMAC signature, expiry & tenant prefix before serving bytes
 */

import { randomUUID } from 'node:crypto';
import { getHeader } from '../../../shared/auth/csrf.mjs';
import { guardProtectedRequest } from '../../../shared/auth/api-guard.mjs';
import { PERMISSIONS } from '../../../modules/authorization/permissions.mjs';

export function createStorageApiHandlers({ authService, storageService, repo, allowedOrigins = ['https://aqar.sd'] }) {
  return {
    async postIssueSignedUrl(req, now = new Date()) {
      const fileId = String(req.body?.fileId ?? '').trim();
      const fileKind = String(req.body?.fileKind ?? 'document').trim(); // 'document' | 'private_media'
      const fileRecord = fileId ? await repo.findPrivateFileById(fileId, fileKind) : null;

      // Require properties.verify for sensitive ownership documents, properties.view for private media
      const requiredPermission =
        fileKind === 'document' ? PERMISSIONS.PROPERTIES_VIEW : PERMISSIONS.PROPERTIES_VIEW;

      const guard = await guardProtectedRequest({
        req: { ...req, method: 'POST' },
        authService,
        repo,
        allowedOrigins,
        requiredPermission,
        resource: fileRecord ? { organizationId: fileRecord.organizationId } : undefined,
        now,
      });
      if (!guard.ok) return guard;

      if (!fileRecord || fileRecord.organizationId !== guard.verifiedContext.organizationId) {
        return {
          status: 404,
          headers: { 'X-Request-Id': guard.requestId },
          body: { error: { code: 'NOT_FOUND', message: 'الملف غير موجود', requestId: guard.requestId } },
        };
      }

      const signed = storageService.issueSignedDownloadUrl({
        verifiedOrganizationId: guard.verifiedContext.organizationId,
        actorUserId: guard.verifiedContext.userId,
        fileRecord,
        ttlSeconds: req.body?.ttlSeconds ?? 120,
        now,
      });

      await repo.appendAuditLog({
        organizationId: guard.verifiedContext.organizationId,
        actorUserId: guard.verifiedContext.userId,
        action: 'storage.signed_url.issued',
        entityType: fileKind,
        entityId: fileRecord.id,
        before: null,
        after: { expiresAt: signed.expiresAt, ttlSeconds: signed.ttlSeconds },
        reason: null,
        requestId: guard.requestId,
        deviceId: guard.session.deviceId,
        ipHash: null,
        createdAt: now,
      });

      return {
        status: 200,
        headers: { 'X-Request-Id': guard.requestId, 'Cache-Control': 'no-store' },
        body: {
          signedUrl: signed.url,
          expiresAt: signed.expiresAt,
          ttlSeconds: signed.ttlSeconds,
          requestId: guard.requestId,
        },
      };
    },

    async getDownloadPrivateFile(req, now = new Date()) {
      const requestId = getHeader(req.headers, 'x-request-id') || randomUUID();
      const verified = storageService.verifySignedDownloadUrl(req.query, now);
      if (!verified.ok) {
        return {
          status: verified.code === 'SIGNED_URL_EXPIRED' ? 410 : 403,
          headers: { 'X-Request-Id': requestId, 'Cache-Control': 'no-store' },
          body: { error: { code: verified.code, message: verified.message, requestId } },
        };
      }

      return {
        status: 200,
        headers: { 'X-Request-Id': requestId, 'Cache-Control': 'private, no-store' },
        body: {
          authorizedDownload: true,
          organizationId: verified.organizationId,
          fileId: verified.fileId,
          storageKey: verified.storageKey,
          requestId,
        },
      };
    },
  };
}
