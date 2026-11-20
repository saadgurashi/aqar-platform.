/**
 * Multi-Dimensional Rate Limiter — منصة عقار 2.0 (Section 3.10 & 11)
 *
 * Enforces rate limits across Account + IP + Device dimensions simultaneously.
 * Production MUST use a shared distributed backend (PostgreSQL `rate_limit_buckets` or Redis).
 * The in-memory store is strictly guarded to refuse running in NODE_ENV=production.
 */

export class PgRateLimitStore {
  /**
   * @param {{ query: (sql: string, params?: unknown[]) => Promise<{ rows: any[] }> }} dbClient
   */
  constructor(dbClient) {
    this.db = dbClient;
  }

  async consume(bucketKey, limit, windowSeconds, blockSeconds, now = new Date()) {
    const sql = `
      INSERT INTO rate_limit_buckets (bucket_key, window_start, window_seconds, hit_count, blocked_until, updated_at)
      VALUES ($1, $2, $3, 1, NULL, $2)
      ON CONFLICT (bucket_key) DO UPDATE SET
        hit_count = CASE
          WHEN rate_limit_buckets.blocked_until IS NOT NULL AND rate_limit_buckets.blocked_until > $2
            THEN rate_limit_buckets.hit_count + 1
          WHEN rate_limit_buckets.window_start + make_interval(secs => rate_limit_buckets.window_seconds) <= $2
            THEN 1
          ELSE rate_limit_buckets.hit_count + 1
        END,
        window_start = CASE
          WHEN rate_limit_buckets.window_start + make_interval(secs => rate_limit_buckets.window_seconds) <= $2
               AND (rate_limit_buckets.blocked_until IS NULL OR rate_limit_buckets.blocked_until <= $2)
            THEN $2
          ELSE rate_limit_buckets.window_start
        END,
        blocked_until = CASE
          WHEN rate_limit_buckets.blocked_until IS NOT NULL AND rate_limit_buckets.blocked_until > $2
            THEN rate_limit_buckets.blocked_until
          WHEN (CASE
                  WHEN rate_limit_buckets.window_start + make_interval(secs => rate_limit_buckets.window_seconds) <= $2 THEN 1
                  ELSE rate_limit_buckets.hit_count + 1
                END) > $4
            THEN $2 + make_interval(secs => $5)
          ELSE NULL
        END,
        updated_at = $2
      RETURNING hit_count, blocked_until;
    `;
    const res = await this.db.query(sql, [bucketKey, now.toISOString(), windowSeconds, limit, blockSeconds]);
    const row = res.rows[0];
    const blockedUntil = row.blocked_until ? new Date(row.blocked_until) : null;
    const allowed = !blockedUntil || blockedUntil <= now;
    const retryAfterSeconds = allowed ? 0 : Math.ceil((blockedUntil.getTime() - now.getTime()) / 1000);
    return { allowed, hitCount: row.hit_count, retryAfterSeconds };
  }
}

/**
 * Strictly for local unit tests — throws immediately if used in production.
 */
export class InMemoryTestRateLimitStore {
  constructor(env = process.env.NODE_ENV) {
    if (env === 'production') {
      throw new Error(
        'SECURITY_POLICY_VIOLATION: InMemoryTestRateLimitStore is forbidden in production; use PgRateLimitStore or Redis.',
      );
    }
    this.buckets = new Map();
  }

  async consume(bucketKey, limit, windowSeconds, blockSeconds, now = new Date()) {
    const nowMs = now.getTime();
    let entry = this.buckets.get(bucketKey);

    if (!entry) {
      entry = { windowStartMs: nowMs, hitCount: 0, blockedUntilMs: null };
      this.buckets.set(bucketKey, entry);
    }

    if (entry.blockedUntilMs && entry.blockedUntilMs > nowMs) {
      entry.hitCount += 1;
      return {
        allowed: false,
        hitCount: entry.hitCount,
        retryAfterSeconds: Math.ceil((entry.blockedUntilMs - nowMs) / 1000),
      };
    }

    if (nowMs - entry.windowStartMs >= windowSeconds * 1000) {
      entry.windowStartMs = nowMs;
      entry.hitCount = 0;
      entry.blockedUntilMs = null;
    }

    entry.hitCount += 1;
    if (entry.hitCount > limit) {
      entry.blockedUntilMs = nowMs + blockSeconds * 1000;
      return {
        allowed: false,
        hitCount: entry.hitCount,
        retryAfterSeconds: blockSeconds,
      };
    }

    return { allowed: true, hitCount: entry.hitCount, retryAfterSeconds: 0 };
  }
}

/**
 * Evaluates rate limit simultaneously across Account, IP, and Device dimensions.
 */
export async function enforceMultiDimensionalRateLimit(store, {
  action,
  accountKey,
  ipKey,
  deviceKey,
  limits = {
    account: { limit: 5, windowSeconds: 300, blockSeconds: 900 },
    ip: { limit: 15, windowSeconds: 300, blockSeconds: 900 },
    device: { limit: 8, windowSeconds: 300, blockSeconds: 900 },
  },
  now = new Date(),
}) {
  const checks = [];
  if (accountKey && limits.account) {
    checks.push({
      dimension: 'account',
      res: await store.consume(
        `${action}:acct:${accountKey}`,
        limits.account.limit,
        limits.account.windowSeconds,
        limits.account.blockSeconds,
        now,
      ),
    });
  }
  if (ipKey && limits.ip) {
    checks.push({
      dimension: 'ip',
      res: await store.consume(
        `${action}:ip:${ipKey}`,
        limits.ip.limit,
        limits.ip.windowSeconds,
        limits.ip.blockSeconds,
        now,
      ),
    });
  }
  if (deviceKey && limits.device) {
    checks.push({
      dimension: 'device',
      res: await store.consume(
        `${action}:dev:${deviceKey}`,
        limits.device.limit,
        limits.device.windowSeconds,
        limits.device.blockSeconds,
        now,
      ),
    });
  }

  const violated = checks.find((c) => !c.res.allowed);
  if (violated) {
    return {
      allowed: false,
      dimension: violated.dimension,
      retryAfterSeconds: violated.res.retryAfterSeconds,
    };
  }

  return { allowed: true, dimension: null, retryAfterSeconds: 0 };
}
