/**
 * PostgreSQL Auth, Identity, RBAC & Private Storage Repository — منصة عقار 2.0
 *
 * Security invariants:
 * - Connects using non-privileged role (`aqar_app_login` inheriting `aqar_app` with NOBYPASSRLS).
 * - Tenant-scoped queries ALWAYS execute inside `withTenantTransaction()` using transaction-local
 *   `set_config('app.organization_id', ..., true)` so pooled connections NEVER leak tenant context.
 * - Pre-auth / session lookup queries use minimal transaction-local system scope and immediately
 *   close/commit so no session parameter persists on the pooled connection.
 */

import { withTenantTransaction } from '../../shared/db/tenant-context.mjs';

export class PgAuthRepository {
  /**
   * @param {Object} deps
   * @param {{ connect: () => Promise<any>, query: (sql: string, params?: unknown[]) => Promise<any> }} deps.pool pg.Pool instance
   */
  constructor({ pool }) {
    if (!pool || typeof pool.connect !== 'function') {
      throw new Error('PG_CONFIG_ERROR: Valid pg.Pool instance is required');
    }
    this.pool = pool;
  }

  /**
   * Executes a callback inside a dedicated checked-out client bound to verified tenant context.
   * Ensures connection is ALWAYS released back to the pool even on rollback/error.
   */
  async runInTenantTx(verifiedContext, work) {
    const client = await this.pool.connect();
    try {
      return await withTenantTransaction(client, verifiedContext, work);
    } finally {
      client.release();
    }
  }

  /**
   * Executes pre-authentication lookup/write inside a clean transaction with explicit
   * transaction-local reset (`app.organization_id = ''`, `app.platform_admin = 'true'`)
   * strictly for identity bootstrap (login/session resolution), never exposed to tenant APIs.
   */
  async #runInAuthBootstrapTx(work) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('app.organization_id', '', true)`);
      await client.query(`SELECT set_config('app.user_id', '', true)`);
      await client.query(`SELECT set_config('app.platform_admin', 'true', true)`);
      const res = await work(client);
      await client.query('COMMIT');
      return res;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  // ---------------------------------------------------------------------------
  // OTP Challenges & Login Attempts
  // ---------------------------------------------------------------------------
  async createOtpChallenge(rec) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const sql = `
        INSERT INTO otp_challenges (
          id, identifier_hash, purpose, code_hash, salt,
          attempts, max_attempts, expires_at, consumed_at, device_id, ip_hash, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        RETURNING *;
      `;
      const { rows } = await tx.query(sql, [
        rec.id,
        rec.identifierHash,
        rec.purpose,
        rec.codeHash,
        rec.salt,
        rec.attempts,
        rec.maxAttempts,
        rec.expiresAt,
        rec.consumedAt,
        rec.deviceId,
        rec.ipHash,
        rec.createdAt,
      ]);
      return mapOtpChallenge(rows[0]);
    });
  }

  async findLatestOtpChallenge(identifierHash, purpose) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT * FROM otp_challenges
         WHERE identifier_hash = $1 AND purpose = $2
         ORDER BY created_at DESC
         LIMIT 1;`,
        [identifierHash, purpose],
      );
      return rows[0] ? mapOtpChallenge(rows[0]) : null;
    });
  }

  async incrementOtpAttempts(id, attempts, consumedAt) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `UPDATE otp_challenges
         SET attempts = $2, consumed_at = COALESCE($3, consumed_at)
         WHERE id = $1;`,
        [id, attempts, consumedAt],
      );
    });
  }

  async consumeOtpChallenge(id, now) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `UPDATE otp_challenges
         SET consumed_at = $2
         WHERE id = $1 AND consumed_at IS NULL;`,
        [id, now],
      );
    });
  }

  async recordLoginAttempt(rec) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `INSERT INTO login_attempts (identifier_hash, device_id, ip_hash, outcome, created_at)
         VALUES ($1, $2, $3, $4, $5);`,
        [rec.identifierHash, rec.deviceId, rec.ipHash, rec.outcome, rec.createdAt],
      );
    });
  }

  // ---------------------------------------------------------------------------
  // Users, Memberships, Roles & Overrides
  // ---------------------------------------------------------------------------
  async findUserByIdentifier(identifier) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, full_name, phone, email, locale, numeral_system, mfa_enabled, status
         FROM users
         WHERE (phone = $1 OR lower(email) = lower($1)) AND deleted_at IS NULL
         LIMIT 1;`,
        [identifier],
      );
      return rows[0] ? mapUser(rows[0]) : null;
    });
  }

  async findUserById(userId) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, full_name, phone, email, locale, numeral_system, mfa_enabled, status
         FROM users
         WHERE id = $1 AND deleted_at IS NULL
         LIMIT 1;`,
        [userId],
      );
      return rows[0] ? mapUser(rows[0]) : null;
    });
  }

  async findActiveMembershipsForUser(userId) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, user_id, organization_id, status, joined_at
         FROM memberships
         WHERE user_id = $1 AND status = 'active'
         ORDER BY created_at ASC;`,
        [userId],
      );
      return rows.map(mapMembership);
    });
  }

  async findMembership(userId, organizationId) {
    return this.runInTenantTx({ userId, organizationId }, async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, user_id, organization_id, status, joined_at
         FROM memberships
         WHERE user_id = $1 AND organization_id = $2
         LIMIT 1;`,
        [userId, organizationId],
      );
      return rows[0] ? mapMembership(rows[0]) : null;
    });
  }

  async findMembershipById(membershipId, verifiedContext = null) {
    if (verifiedContext) {
      return this.runInTenantTx(verifiedContext, async (tx) => {
        const { rows } = await tx.query(
          `SELECT id, user_id, organization_id, status, joined_at FROM memberships WHERE id = $1 LIMIT 1;`,
          [membershipId],
        );
        return rows[0] ? mapMembership(rows[0]) : null;
      });
    }
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, user_id, organization_id, status, joined_at FROM memberships WHERE id = $1 LIMIT 1;`,
        [membershipId],
      );
      return rows[0] ? mapMembership(rows[0]) : null;
    });
  }

  async listMembershipsByOrg(organizationId, actorUserId) {
    return this.runInTenantTx({ userId: actorUserId, organizationId }, async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, user_id, organization_id, status, joined_at
         FROM memberships
         ORDER BY created_at ASC;`,
      );
      return rows.map(mapMembership);
    });
  }

  async updateMembershipStatus(membershipId, organizationId, status, now, actorUserId) {
    return this.runInTenantTx({ userId: actorUserId, organizationId }, async (tx) => {
      await tx.query(
        `UPDATE memberships
         SET status = $2, updated_at = $3
         WHERE id = $1 AND organization_id = $4;`,
        [membershipId, status, now, organizationId],
      );
    });
  }

  async findRoleKeysForMembership(membershipId, organizationId) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT r.key
         FROM user_role_assignments ura
         JOIN roles r ON r.id = ura.role_id
         WHERE ura.membership_id = $1 AND ura.organization_id = $2;`,
        [membershipId, organizationId],
      );
      return rows.map((r) => r.key);
    });
  }

  async assignRoleToMembership(membershipId, organizationId, roleKey, actorUserId) {
    return this.runInTenantTx({ userId: actorUserId, organizationId }, async (tx) => {
      const roleRes = await tx.query(
        `SELECT id FROM roles WHERE key = $1 AND (is_system = true OR organization_id = $2) LIMIT 1;`,
        [roleKey, organizationId],
      );
      if (!roleRes.rows[0]) {
        throw new Error(`ROLE_NOT_FOUND: ${roleKey}`);
      }
      await tx.query(
        `INSERT INTO user_role_assignments (organization_id, membership_id, role_id, assigned_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT DO NOTHING;`,
        [organizationId, membershipId, roleRes.rows[0].id, actorUserId],
      );
    });
  }

  async findPermissionOverrides(membershipId, organizationId) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT p.key AS permission_key, po.effect, po.expires_at
         FROM permission_overrides po
         JOIN permissions p ON p.id = po.permission_id
         WHERE po.membership_id = $1 AND po.organization_id = $2;`,
        [membershipId, organizationId],
      );
      return rows.map((r) => ({
        permissionKey: r.permission_key,
        effect: r.effect,
        expiresAt: r.expires_at,
      }));
    });
  }

  // ---------------------------------------------------------------------------
  // Device Sessions & MFA Recovery Codes
  // ---------------------------------------------------------------------------
  async createSession(s) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `INSERT INTO device_sessions (
          id, user_id, active_organization_id, device_id, token_hash,
          csrf_token_hash, issued_at, last_seen_at, idle_timeout_at, expires_at, revoked_at, revoked_reason
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        RETURNING *;`,
        [
          s.id,
          s.userId,
          s.activeOrganizationId,
          s.deviceId,
          s.tokenHash,
          s.csrfTokenHash,
          s.issuedAt,
          s.lastSeenAt,
          s.idleTimeoutAt,
          s.expiresAt,
          s.revokedAt,
          s.revokedReason,
        ],
      );
      return mapSession(rows[0]);
    });
  }

  async findSessionByTokenHash(tokenHash) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const { rows } = await tx.query(
        `SELECT * FROM device_sessions WHERE token_hash = $1 LIMIT 1;`,
        [tokenHash],
      );
      return rows[0] ? mapSession(rows[0]) : null;
    });
  }

  async touchSession(sessionId, lastSeenAt, idleTimeoutAt) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `UPDATE device_sessions SET last_seen_at = $2, idle_timeout_at = $3 WHERE id = $1;`,
        [sessionId, lastSeenAt, idleTimeoutAt],
      );
    });
  }

  async revokeSession(sessionId, reason, now) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `UPDATE device_sessions
         SET revoked_at = $3, revoked_reason = $2
         WHERE id = $1 AND revoked_at IS NULL;`,
        [sessionId, reason, now],
      );
    });
  }

  async revokeUserSessionsForOrg(userId, organizationId, reason, now) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const res = await tx.query(
        `UPDATE device_sessions
         SET revoked_at = $4, revoked_reason = $3
         WHERE user_id = $1 AND active_organization_id = $2 AND revoked_at IS NULL;`,
        [userId, organizationId, reason, now],
      );
      return res.rowCount ?? 0;
    });
  }

  async consumeMfaRecoveryCode(userId, codeHash, now) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      const res = await tx.query(
        `UPDATE mfa_recovery_codes
         SET used_at = $3
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL;`,
        [userId, codeHash, now],
      );
      return (res.rowCount ?? 0) === 1;
    });
  }

  // ---------------------------------------------------------------------------
  // Private Documents & Media (RLS Enforced)
  // ---------------------------------------------------------------------------
  async findPrivateFileById(fileId, fileKind = 'document', verifiedContext = null) {
    const table = fileKind === 'private_media' ? 'property_media' : 'property_documents';
    const keyCol = fileKind === 'private_media' ? 'storage_key' : 'private_storage_key';

    const queryFn = async (tx) => {
      const { rows } = await tx.query(
        `SELECT id, organization_id, ${keyCol} AS storage_key FROM ${table} WHERE id = $1 AND deleted_at IS NULL LIMIT 1;`,
        [fileId],
      );
      if (!rows[0]) return null;
      return {
        id: rows[0].id,
        organizationId: rows[0].organization_id,
        privateStorageKey: rows[0].storage_key,
        storageKey: rows[0].storage_key,
      };
    };

    if (verifiedContext) {
      return this.runInTenantTx(verifiedContext, queryFn);
    }
    return this.#runInAuthBootstrapTx(queryFn);
  }

  // ---------------------------------------------------------------------------
  // Append-Only Audit Logs & Security Events
  // ---------------------------------------------------------------------------
  async appendAuditLog(rec) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `INSERT INTO audit_logs (
          organization_id, actor_user_id, action, entity_type, entity_id,
          before, after, reason, request_id, device_id, ip_hash, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12);`,
        [
          rec.organizationId,
          rec.actorUserId,
          rec.action,
          rec.entityType,
          rec.entityId,
          rec.before ? JSON.stringify(rec.before) : null,
          rec.after ? JSON.stringify(rec.after) : null,
          rec.reason,
          rec.requestId,
          rec.deviceId,
          rec.ipHash,
          rec.createdAt ?? new Date(),
        ],
      );
    });
  }

  async recordSecurityEvent(rec) {
    return this.#runInAuthBootstrapTx(async (tx) => {
      await tx.query(
        `INSERT INTO security_events (
          organization_id, user_id, event_type, severity, details, request_id, ip_hash, created_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8);`,
        [
          rec.organizationId,
          rec.userId,
          rec.eventType,
          rec.severity,
          JSON.stringify(rec.details ?? {}),
          rec.requestId,
          rec.ipHash ?? null,
          rec.createdAt ?? new Date(),
        ],
      );
    });
  }
}

function mapOtpChallenge(row) {
  return {
    id: row.id,
    identifierHash: row.identifier_hash,
    purpose: row.purpose,
    codeHash: row.code_hash,
    salt: row.salt,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    expiresAt: row.expires_at,
    consumedAt: row.consumed_at,
    deviceId: row.device_id,
    ipHash: row.ip_hash,
    createdAt: row.created_at,
  };
}

function mapUser(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    phone: row.phone,
    email: row.email,
    locale: row.locale,
    numeralSystem: row.numeral_system,
    mfaEnabled: row.mfa_enabled,
    status: row.status,
  };
}

function mapMembership(row) {
  return {
    id: row.id,
    userId: row.user_id,
    organizationId: row.organization_id,
    status: row.status,
    joinedAt: row.joined_at,
  };
}

function mapSession(row) {
  return {
    id: row.id,
    userId: row.user_id,
    activeOrganizationId: row.active_organization_id,
    deviceId: row.device_id,
    tokenHash: row.token_hash,
    csrfTokenHash: row.csrf_token_hash,
    issuedAt: row.issued_at,
    lastSeenAt: row.last_seen_at,
    idleTimeoutAt: row.idle_timeout_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    revokedReason: row.revoked_reason,
  };
}
