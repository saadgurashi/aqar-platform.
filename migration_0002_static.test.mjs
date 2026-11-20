import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const sql = fs
  .readFileSync(path.resolve('db/migrations/0002_auth_otp_mfa_rate_limits.sql'), 'utf8')
  .replace(/--.*$/gm, '');

test('Migration 0002 stores hashed OTPs & recovery codes only (never plaintext code column)', () => {
  assert.match(sql, /CREATE TABLE otp_challenges/i);
  assert.match(sql, /code_hash text NOT NULL/i);
  assert.match(sql, /salt text NOT NULL/i);
  assert.match(sql, /max_attempts integer NOT NULL/i);
  assert.match(sql, /consumed_at timestamptz NULL/i);
  assert.doesNotMatch(sql, /\botp_code\b|\bplaintext\b/i);
});

test('Migration 0002 enables and forces RLS on mfa_recovery_codes and adds distributed rate_limit_buckets', () => {
  assert.match(sql, /ALTER TABLE mfa_recovery_codes ENABLE ROW LEVEL SECURITY;/i);
  assert.match(sql, /ALTER TABLE mfa_recovery_codes FORCE ROW LEVEL SECURITY;/i);
  assert.match(sql, /CREATE TABLE rate_limit_buckets/i);
  assert.match(sql, /idle_timeout_at timestamptz/i);
  assert.match(sql, /csrf_token_hash text/i);
});
