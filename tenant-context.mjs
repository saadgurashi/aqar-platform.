/**
 * PostgreSQL Tenant Context Transaction Wrapper — منصة عقار 2.0 (Section 3.5)
 *
 * Sets transaction-local (`is_local = true`) PostgreSQL session parameters
 * so tenant context NEVER leaks across reused connections in a connection pool.
 * Fails closed if organizationId or userId is missing or malformed.
 */

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function assertValidUuid(value, fieldName) {
  if (typeof value !== 'string' || !UUID_REGEX.test(value)) {
    throw new Error(`FAIL_CLOSED: Invalid or missing UUID for ${fieldName}`);
  }
}

/**
 * Executes a callback inside a PostgreSQL transaction bound strictly to a verified tenant context.
 *
 * @template T
 * @param {{ query: (sql: string, params?: unknown[]) => Promise<unknown> }} client pg PoolClient
 * @param {{ userId: string, organizationId: string, isPlatformAdmin?: boolean }} verifiedContext
 * @param {(client: any) => Promise<T>} work
 * @returns {Promise<T>}
 */
export async function withTenantTransaction(client, verifiedContext, work) {
  if (!client || typeof client.query !== 'function') {
    throw new Error('FAIL_CLOSED: Valid PostgreSQL client is required');
  }
  if (!verifiedContext) {
    throw new Error('FAIL_CLOSED: Tenant context is required (background jobs cannot run without context)');
  }

  assertValidUuid(verifiedContext.userId, 'userId');
  assertValidUuid(verifiedContext.organizationId, 'organizationId');

  const isPlatformAdmin = verifiedContext.isPlatformAdmin === true ? 'true' : 'false';

  await client.query('BEGIN');
  try {
    // 3rd argument `true` binds setting strictly to the current transaction (prevents pool leakage)
    await client.query(`SELECT set_config('app.user_id', $1, true)`, [verifiedContext.userId]);
    await client.query(`SELECT set_config('app.organization_id', $1, true)`, [verifiedContext.organizationId]);
    await client.query(`SELECT set_config('app.platform_admin', $1, true)`, [isPlatformAdmin]);

    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }
}
