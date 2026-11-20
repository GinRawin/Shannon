/**
 * Offline fixture test for the Java source/sink candidate retriever.
 *
 * Run `pnpm --filter @shannon/worker build` first, then:
 *   node scripts/test-java-security-candidates.mjs
 *
 * The fixture repository under scripts/fixtures/java-security/repo is copied into a temporary
 * directory so the workspace cache never touches the checked-in fixtures. Assertions map onto the
 * acceptance cases in Shannon_Java_Source_Sink_Agent_Tool_开发实施文档.md (§6.4, §11.1, §11.2).
 */
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findSecurityCandidates,
  getSecurityIndex,
  loadSecurityCandidatesConfig,
  resetSecurityIndexCache,
} from '../apps/worker/dist/services/java-security/index.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixture = path.join(repoRoot, 'scripts', 'fixtures', 'java-security', 'repo');
const nonJavaFixture = path.join(repoRoot, 'scripts', 'fixtures', 'java-security', 'non-java');
const malformedFixture = path.join(repoRoot, 'scripts', 'fixtures', 'java-security', 'malformed');

const dir = await mkdtemp(path.join(tmpdir(), 'shannon-jsec-'));
await cp(fixture, dir, { recursive: true });
const nonJavaDir = await mkdtemp(path.join(tmpdir(), 'shannon-jsec-nonjava-'));
await cp(nonJavaFixture, nonJavaDir, { recursive: true });
const malformedDir = await mkdtemp(path.join(tmpdir(), 'shannon-jsec-malformed-'));
await cp(malformedFixture, malformedDir, { recursive: true });

async function lineOf(relative, needle) {
  const text = await readFile(path.join(dir, relative), 'utf8');
  const index = text.split('\n').findIndex((line) => line.includes(needle));
  assert.ok(index >= 0, `fixture ${relative} must contain ${needle}`);
  return index + 1;
}

function at(candidates, relative, line) {
  return candidates.find((candidate) => candidate.file.endsWith(relative) && candidate.line === line);
}

const dao = 'src/main/java/app/UserDao.java';
const handler = 'src/main/java/app/Handler.java';
const ssrf = 'src/main/java/app/SsrfClient.java';

const lines = {
  sqlLiteral: await lineOf(dao, 'stmt.executeQuery("SELECT * FROM users")'),
  sqlConcat: await lineOf(dao, 'WHERE id=" + id'),
  sqlLocal: await lineOf(dao, 'stmt.executeQuery(sql)'),
  sqlFormatArg: await lineOf(dao, 'String.format("SELECT * FROM users WHERE id=%s", id)'),
  sqlSameName: await lineOf(dao, 'dao.executeQuery(input)'),
  sqlUnknown: await lineOf(dao, 'dao.executeSql(input)'),
  httpParamId: await lineOf(handler, 'request.getParameter("id")'),
  httpParamV: await lineOf(handler, 'request.getParameter("v")'),
  principal: await lineOf(handler, 'request.getUserPrincipal()'),
  isUserInRole: await lineOf(handler, 'boolean admin = request.isUserInRole("ADMIN")'),
  execDynamic: await lineOf(handler, 'exec("ping " + host)'),
  execConstant: await lineOf(handler, 'exec("ls")'),
  processBuilder: await lineOf(handler, 'new ProcessBuilder("ping", host).start()'),
  xssConstant: await lineOf(handler, 'out.write("<h1>Hello</h1>")'),
  xssDynamic: await lineOf(handler, 'out.write(v)'),
  formatConstant: await lineOf(handler, 'String.format("123", userInput)'),
  formatDynamic: await lineOf(handler, 'String.format("%s", userInput)'),
  formatUnknown: await lineOf(handler, 'String.format(dynamicFormat, userInput)'),
  hasRole: await lineOf(handler, 'security.hasRole("ADMIN")'),
  urlCtor: await lineOf(ssrf, 'new URL(target).openConnection()'),
  restTemplate: await lineOf(ssrf, 'restTemplate.getForObject(target, String.class)'),
};

const config = loadSecurityCandidatesConfig();
const query = (input) => findSecurityCandidates(input, { sourceDir: dir, config });

let checks = 0;
const ok = (condition, message) => {
  assert.ok(condition, message);
  checks += 1;
};

// --- §6.4 / §11.1: SQL -----------------------------------------------------------------------
{
  const injection = await query({ vulnerability_type: 'injection', limit: 100 });
  ok(injection.status === 'complete', 'injection recall status is complete');
  ok(injection.stats.matched_before_filter >= injection.returned, 'matched count covers returned count');
  ok(at(injection.candidates, dao, lines.sqlLiteral) === undefined, 'fully constant SQL is filtered');
  const concat = at(injection.candidates, dao, lines.sqlConcat);
  ok(concat !== undefined, 'SQL concatenated with a parameter is retained');
  ok(concat.role === 'sink' && concat.category === 'sql', 'concatenated SQL is a sql sink');
  ok(concat.constant_state === 'dynamic', 'concatenated SQL is dynamic');
  ok(at(injection.candidates, dao, lines.sqlLocal) === undefined, 'single-assignment literal local passed to SQL is filtered');
  const formatted = at(injection.candidates, dao, lines.sqlFormatArg);
  ok(formatted !== undefined, 'String.format-derived SQL is retained as a transform');
  ok(
    injection.stats.filtered_constant >= 1,
    'at least one constant candidate was filtered',
  );
}

// --- §11.1: command --------------------------------------------------------------------------
{
  const injection = await query({ vulnerability_type: 'injection', limit: 100 });
  const exec = at(injection.candidates, handler, lines.execDynamic);
  ok(exec !== undefined && exec.category === 'command', 'dynamic command is retained');
  ok(at(injection.candidates, handler, lines.execConstant) === undefined, 'fully constant command is filtered');
  const pb = at(injection.candidates, handler, lines.processBuilder);
  ok(pb !== undefined && pb.category === 'command', 'ProcessBuilder construction is retained');
}

// --- §11.1: sources / XSS / SSRF / auth / authz ---------------------------------------------
{
  const injection = await query({ vulnerability_type: 'injection', limit: 100 });
  const source = at(injection.candidates, handler, lines.httpParamId);
  ok(source !== undefined && source.role === 'source', 'getParameter is a source even with a fixed key');
  ok(source.constant_state === 'not_applicable', 'source is never constant-filtered');

  const xss = await query({ vulnerability_type: 'xss', limit: 100 });
  ok(at(xss.candidates, handler, lines.xssConstant) === undefined, 'fixed HTML output is filtered');
  const xssDynamic = at(xss.candidates, handler, lines.xssDynamic);
  ok(xssDynamic !== undefined && xssDynamic.role === 'sink', 'dynamic output is retained');

  const ssrfResult = await query({ vulnerability_type: 'ssrf', limit: 100 });
  ok(at(ssrfResult.candidates, ssrf, lines.urlCtor) !== undefined, 'new URL(target) is an SSRF sink');
  ok(at(ssrfResult.candidates, ssrf, lines.restTemplate) !== undefined, 'RestTemplate call is an SSRF sink');

  const auth = await query({ vulnerability_type: 'auth', limit: 100 });
  ok(at(auth.candidates, handler, lines.principal) !== undefined, 'getUserPrincipal is an auth source');

  const authz = await query({ vulnerability_type: 'authz', limit: 100 });
  const role = at(authz.candidates, handler, lines.isUserInRole);
  ok(role !== undefined && role.role === 'security_boundary', 'isUserInRole is an authz boundary');
  const named = at(authz.candidates, handler, lines.hasRole);
  ok(named !== undefined && named.role === 'security_boundary', 'hasRole with a fixed role is retained');
}

// --- §6.4: String.format transform -----------------------------------------------------------
{
  const injection = await query({ vulnerability_type: 'injection', limit: 100 });
  ok(at(injection.candidates, handler, lines.formatConstant) === undefined, 'format with no referenced arg is filtered');
  const fmtDynamic = at(injection.candidates, handler, lines.formatDynamic);
  ok(fmtDynamic !== undefined && fmtDynamic.role === 'transform', 'format referencing a dynamic arg is retained');
  ok(fmtDynamic.constant_state === 'dynamic', 'format referencing a dynamic arg is dynamic');
  ok(at(injection.candidates, handler, lines.formatUnknown) !== undefined, 'runtime format string is retained');
}

// --- §11.1: function-name search -------------------------------------------------------------
{
  const byName = await query({ vulnerability_type: 'injection', limit: 100, function_name: 'executeQuery' });
  const strong = at(byName.candidates, dao, lines.sqlConcat);
  ok(strong !== undefined && strong.role === 'sink', 'type-resolved same-name call is a classified sink');
  ok(strong.resolved_api === 'java.sql.Statement.executeQuery', 'resolved_api names the full API');
  const weak = at(byName.candidates, dao, lines.sqlSameName);
  ok(weak !== undefined && weak.role === 'unclassified', 'unproven same-name call is unclassified');
  ok(weak.confidence === 'name_only' && weak.rule_ids.length === 0, 'unclassified match carries no rule ids');

  const custom = await query({ vulnerability_type: 'injection', limit: 100, function_name: 'executeSql' });
  const customHit = at(custom.candidates, dao, lines.sqlUnknown);
  ok(customHit !== undefined && customHit.role === 'unclassified', 'dictionary-absent method is unclassified');
  ok(customHit.confidence === 'name_only', 'dictionary-absent method is name_only');
}

// --- §7 / §11.1: deterministic pagination ----------------------------------------------------
{
  const full = await query({ vulnerability_type: 'injection', limit: 100 });
  const pageIds = [];
  let cursor;
  let guard = 0;
  for (;;) {
    const page = await query({ vulnerability_type: 'injection', limit: 3, ...(cursor ? { cursor } : {}) });
    assert.equal(page.status, 'complete');
    for (const candidate of page.candidates) pageIds.push(candidate.id);
    if (!page.has_more) break;
    cursor = page.next_cursor;
    guard += 1;
    assert.ok(guard < 100, 'pagination terminates');
  }
  ok(pageIds.length === full.candidates.length, 'paged traversal returns every candidate');
  ok(new Set(pageIds).size === pageIds.length, 'paged traversal never repeats a candidate');
  ok(
    JSON.stringify(pageIds) === JSON.stringify(full.candidates.map((c) => c.id)),
    'paged order matches the deterministic full order',
  );

  const first = await query({ vulnerability_type: 'injection', limit: 3 });
  const tampered = `${first.next_cursor.slice(0, -1)}${first.next_cursor.endsWith('A') ? 'B' : 'A'}`;
  const invalid = await query({ vulnerability_type: 'injection', limit: 3, cursor: tampered });
  ok(invalid.status === 'invalid_cursor', 'a mismatched cursor is rejected explicitly');
}

// --- §8: single-flight + cache reuse ---------------------------------------------------------
{
  resetSecurityIndexCache();
  const fresh = await mkdtemp(path.join(tmpdir(), 'shannon-jsec-conc-'));
  await cp(fixture, fresh, { recursive: true });
  const results = await Promise.all(
    Array.from({ length: 5 }, () => findSecurityCandidates({ vulnerability_type: 'injection', limit: 5 }, { sourceDir: fresh, config })),
  );
  ok(results.every((result) => result.status === 'complete'), '5 concurrent first requests all succeed');
  const ids = new Set(results.map((result) => result.snapshot_id));
  ok(ids.size === 1, 'concurrent requests share one snapshot');

  const firstHandle = await getSecurityIndex(fresh, config);
  const secondHandle = await getSecurityIndex(fresh, config);
  ok(firstHandle.index.snapshotId === secondHandle.index.snapshotId, 'index snapshot is stable');
}

// --- §11.2: non-Java project falls back cleanly ----------------------------------------------
{
  const result = await findSecurityCandidates({ vulnerability_type: 'injection', limit: 10 }, { sourceDir: nonJavaDir, config });
  ok(result.status === 'complete', 'non-Java project returns complete');
  ok(result.returned === 0 && result.candidates.length === 0, 'non-Java project returns no candidates');
  ok(result.stats.files_scanned === 0, 'non-Java project scans zero Java files');
}

// --- §5.3 / §11.3: MyBatis XML coverage gap is always disclosed --------------------------------
{
  const fresh = await findSecurityCandidates({ vulnerability_type: 'injection', limit: 5 }, { sourceDir: dir, config });
  const hasGap = (result) => result.warnings.some((warning) => warning.includes('MyBatis'));
  ok(hasGap(fresh), 'a cold query discloses the MyBatis XML coverage gap');

  const handle = await getSecurityIndex(dir, config);
  ok(handle.fromCache, 'the second index request is served from cache');
  ok(
    handle.warnings.some((warning) => warning.includes('MyBatis')),
    'a cache hit still discloses the MyBatis XML coverage gap',
  );
}

// --- §11.1: file errors degrade to partial without blocking the caller -----------------------
{
  const result = await findSecurityCandidates(
    { vulnerability_type: 'injection', limit: 10 },
    { sourceDir: malformedDir, config },
  );
  ok(result.status === 'partial', 'an unparsable file yields partial, not complete');
  ok(result.stats.parse_errors >= 1, 'the count of unparsable files is disclosed');
  ok(result.warnings.some((warning) => warning.includes('failed to parse')), 'the parser failure is disclosed');
}

// --- §12: disable switch ---------------------------------------------------------------------
{
  const disabled = await findSecurityCandidates(
    { vulnerability_type: 'injection', limit: 10 },
    { sourceDir: dir, config: { ...config, enabled: false } },
  );
  ok(disabled.status === 'unavailable', 'disabled feature returns unavailable');
  ok(disabled.candidates.length === 0, 'disabled feature returns no candidates');
}

console.log(`java-security-candidates: ${checks} assertions passed`);
