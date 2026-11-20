import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ALL_PERMISSION_KEYS } from '../../src/modules/authorization/permissions.mjs';

const migrationPath = path.resolve('db/migrations/0001_core_identity_rbac_rls.sql');
const rawSql = fs.readFileSync(migrationPath, 'utf8');
// Strip single-line SQL comments before security assertions
const sql = rawSql.replace(/--.*$/gm, '');

test('SQL Migration 0001 forbids BYPASSRLS on application role aqar_app', () => {
  assert.match(sql, /CREATE ROLE aqar_app[\s\S]*NOBYPASSRLS/i);
  assert.doesNotMatch(sql, /\b(CREATE|ALTER)\s+ROLE\s+aqar_app\b[^;]*\bBYPASSRLS\b/i);
});

test('SQL Migration 0001 enables AND forces RLS on all tenant-owned and security tables', () => {
  const rlsTables = [
    'organizations',
    'memberships',
    'roles',
    'user_role_assignments',
    'permission_overrides',
    'device_sessions',
    'audit_logs',
    'security_events',
  ];

  for (const tbl of rlsTables) {
    assert.match(sql, new RegExp(`ALTER TABLE ${tbl} ENABLE ROW LEVEL SECURITY;`, 'i'), `Missing ENABLE RLS on ${tbl}`);
    assert.match(sql, new RegExp(`ALTER TABLE ${tbl} FORCE ROW LEVEL SECURITY;`, 'i'), `Missing FORCE RLS on ${tbl}`);
  }
});

test('SQL Migration 0001 enforces composite cross-tenant FK and append-only audit_logs', () => {
  assert.match(sql, /UNIQUE \(organization_id, id\)/i);
  assert.match(sql, /FOREIGN KEY \(organization_id, membership_id\)\s+REFERENCES memberships\(organization_id, id\)/i);
  assert.match(sql, /BEFORE UPDATE ON audit_logs/i);
  assert.match(sql, /BEFORE DELETE ON audit_logs/i);
  assert.match(sql, /REVOKE UPDATE, DELETE ON audit_logs FROM aqar_app/i);
});

test('SQL Migration 0001 uses UTC timestamptz and forbids floating point types', () => {
  assert.match(sql, /timestamptz/i);
  assert.doesNotMatch(sql, /\b(float4|float8|double precision|real)\b/i);
});

test('SQL Migration 0001 seeds every permission key defined in Permission Registry', () => {
  for (const key of ALL_PERMISSION_KEYS) {
    assert.ok(sql.includes(`'${key}'`), `Missing SQL seed for permission key: ${key}`);
  }
});
