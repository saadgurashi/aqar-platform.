import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const pgRepoSrc = fs.readFileSync(path.resolve('src/modules/identity/pg-auth.repository.mjs'), 'utf8');
const pgTestSrc = fs.readFileSync(path.resolve('tests/integration/pg_rls.integration.test.mjs'), 'utf8');
const ciYml = fs.readFileSync(path.resolve('.github/workflows/ci.yml'), 'utf8');

test('PgAuthRepository binds tenant transactions via withTenantTransaction and always releases pooled clients', () => {
  assert.match(pgRepoSrc, /withTenantTransaction/);
  assert.match(pgRepoSrc, /finally\s*\{\s*client\.release\(\);/s);
  assert.match(pgRepoSrc, /set_config\('app\.organization_id', '', true\)/);
});

test('pg_rls.integration.test.mjs fails hard when REQUIRE_PG_INTEGRATION=true without DB URLs', () => {
  assert.match(pgTestSrc, /REQUIRE_PG_INTEGRATION/);
  assert.match(pgTestSrc, /GATE_BLOCKED/);
  assert.match(pgTestSrc, /rolbypassrls/);
  assert.match(pgTestSrc, /relforcerowsecurity/);
  assert.match(pgTestSrc, /INTENTIONAL_ROLLBACK_TEST/);
});

test('GitHub Actions ci.yml enforces PostgreSQL 16, NOBYPASSRLS role, 0001-0003 order, matrix, integration, and artifact upload', () => {
  assert.match(ciYml, /postgres:16-alpine/);
  assert.match(ciYml, /pg_isready/);
  assert.match(ciYml, /NOBYPASSRLS NOSUPERUSER/);
  assert.match(ciYml, /0001_core_identity_rbac_rls\.sql/);
  assert.match(ciYml, /0002_auth_otp_mfa_rate_limits\.sql/);
  assert.match(ciYml, /0003_properties_documents_storage_rls\.sql/);
  assert.match(ciYml, /rls_isolation_matrix\.sql/);
  assert.match(ciYml, /pg_rls\.integration\.test\.mjs/);
  assert.match(ciYml, /REQUIRE_PG_INTEGRATION:\s*'true'/);
  assert.match(ciYml, /actions\/upload-artifact@v4/);
});
