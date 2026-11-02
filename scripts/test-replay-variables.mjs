// Offline regressions for plan scoping, dynamic refresh and Exploit-to-Record handoff.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const temporary = await mkdtemp('/tmp/shannon-replay-variables-');
try {
  await run(process.execPath, [
    'node_modules/typescript/bin/tsc', '-p', 'apps/worker/tsconfig.json',
    '--outDir', `${temporary}/dist`, '--incremental', 'false',
  ], { cwd: root });
  await symlink(`${root}/apps/worker/node_modules`, `${temporary}/node_modules`);
  const load = (name) => import(pathToFileURL(`${temporary}/dist/${name}.js`));
  const {
    createReplayVariableResolver, generateTotp, loadReplayResponses,
    loadReplayVariableDefinitions, missingReplayVariables, resolveReplayVariables, updateReplayVariables,
  } = await load('services/replay-variables');
  const { createExploitCollector } = await load('collectors/exploit-collector');
  const { persistCapturedTrace } = await load('services/capture-http-request');
  const target = 'https://fixture.invalid';
  const dir = `${temporary}/deliverables`;
  await mkdir(dir);
  const plan = (suffix = '') => ({ steps: [{
    method: 'GET', url: '${BASE_URL}/proof' + suffix,
    expect: { status: 200, body_contains: 'protected-record' },
  }] });
  const browserPlan = {
    steps: [{ action: 'goto', url: '${BASE_URL}/?input=${BROWSER_INPUT}&marker=${XSS_MARKER}' }],
  };
  const expired = { kind: 'static', value: 'old-fixture', ttl_seconds: 1, updated_at: '2000-01-01T00:00:00Z' };
  const resolve = createReplayVariableResolver(dir, target);
  const inherited = {
    OLD_TOKEN: expired,
    UNUSED_EXTRACT: { kind: 'response_extract', source_finding: 'AUTH-99', pointer: 'missing' },
    UNUSED_OTP: { kind: 'totp', value: 'invalid base32!' },
  };
  assert.deepEqual(await resolve('AUTH-02', inherited, { httpPlan: plan() }), {
    values: { BASE_URL: target }, diagnostics: [],
  });
  assert.deepEqual((await resolve('AUTH-02', { ...inherited, INPUT: 'current' }, {
    httpPlan: plan('?input=${INPUT}'),
  })).values, { BASE_URL: target, INPUT: 'current' });
  const browserOnly = await resolve('XSS-02', { ...inherited, BROWSER_INPUT: 'current' }, { browserPlan });
  assert.deepEqual(browserOnly.values, { BASE_URL: target, BROWSER_INPUT: 'current' });
  assert.deepEqual(browserOnly.diagnostics.map((item) => item.name), ['BROWSER_INPUT']);
  const missing = await resolve('AUTH-02', inherited, { httpPlan: plan('?input=${INPUT}') });
  assert.deepEqual(missing.diagnostics.map(({ name, status }) => [name, status]), [['INPUT', 'missing']]);
  const requiredExpired = await resolve('AUTH-02', { TOKEN: expired }, { httpPlan: plan('?token=${TOKEN}') });
  assert.equal(requiredExpired.diagnostics[0].status, 'expired');
  console.log('PASS initial/retry HTTP and browser resolution ignore obsolete variables, but reject missing or expired required inputs');

  const extractedPlan = {
    setup: [{ method: 'POST', url: '${BASE_URL}/login', save_json: { TOKEN: 'data.token' } }],
    ...plan('?token=${TOKEN}'),
  };
  const extracted = await resolve('AUTH-02', { TOKEN: expired }, { httpPlan: extractedPlan });
  assert.deepEqual(extracted.diagnostics, [], 'A token produced by setup is not a saved external input');
  assert.equal(extracted.values.TOKEN, undefined, 'A stale saved token must not shadow response extraction');
  assert.deepEqual(missingReplayVariables({
    ...extractedPlan, setup: [{ method: 'POST', url: '${BASE_URL}/login?input=${INPUT}', save_json: { TOKEN: 'data.token' } }],
  }, {}), ['INPUT']);
  assert.deepEqual(missingReplayVariables({
    steps: [plan('?token=${TOKEN}').steps[0], { method: 'POST', url: '${BASE_URL}/login', save_json: { TOKEN: 'data.token' } }],
  }, {}), ['TOKEN'], 'A later extraction cannot supply an earlier request');
  console.log('PASS input scoping respects setup/main/cleanup extraction order');

  const now = Date.parse('2026-11-02T12:00:00Z');
  const refresh = (policy, extra = {}) => ({ TOKEN: {
    kind: 'response_extract', source_finding: 'AUTH-01', pointer: '/data/token',
    refresh: policy, ttl_seconds: 60, updated_at: expired.updated_at, ...extra,
  } });
  const snapshot = (token, timestamp) => ({
    responseBodies: new Map([['AUTH-01', { data: { token } }]]),
    responseCapturedAt: new Map([['AUTH-01', timestamp]]),
  });
  const cache = new Map();
  const attempt = (definitions, clock, token, timestamp, memory = cache) => resolveReplayVariables({
    definitions, baseUrl: target, now: clock, cache: memory, ...snapshot(token, timestamp),
  });
  assert.equal(attempt(refresh('each_attempt'), now, 'fresh-1', now).values.TOKEN, 'fresh-1');
  assert.equal(attempt(refresh('each_attempt'), now + 1000, 'fresh-2', now + 1000).values.TOKEN, 'fresh-2');
  assert.equal(attempt(refresh('each_attempt'), now + 61_000, 'stale', now).diagnostics[0].status, 'expired');
  assert.equal(attempt(refresh('each_attempt'), now + 62_000, 'fresh-3', now + 62_000).values.TOKEN, 'fresh-3');
  console.log('PASS each_attempt reads the newest response despite old definition metadata and refuses stale source tokens');

  cache.clear();
  assert.equal(attempt(refresh('on_ttl_expiry'), now, 'cached', now).values.TOKEN, 'cached');
  assert.equal(attempt(refresh('on_ttl_expiry'), now + 30_000, 'newer', now + 30_000).values.TOKEN, 'cached');
  assert.equal(attempt(refresh('on_ttl_expiry'), now + 61_000, 'renewed', now + 61_000).values.TOKEN, 'renewed');
  assert.equal(attempt(refresh('on_ttl_expiry'), now + 122_000, 'renewed', now + 61_000).diagnostics[0].status, 'expired');
  assert.equal(cache.has('TOKEN'), false, 'Expired values must be evicted rather than receiving a new local TTL');
  cache.clear();
  attempt(refresh('on_ttl_expiry'), now, 'old-definition', now);
  assert.equal(attempt(refresh('on_ttl_expiry', { pointer: 'newToken' }), now + 1000, 'unused', now).diagnostics[0].status, 'extract_failed');
  assert.equal(resolveReplayVariables({ definitions: refresh('each_attempt'), baseUrl: target, now,
    responseBodies: snapshot('no-timestamp', now).responseBodies,
  }).diagnostics[0].status, 'expired');
  assert.equal(resolveReplayVariables({ definitions: refresh('each_attempt'), baseUrl: target, now }).diagnostics[0].status, 'extract_failed');
  console.log('PASS on_ttl_expiry caches only until source expiry, invalidates changed definitions and refuses missing timestamps/sources');

  const seed = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  for (const policy of ['each_attempt', 'on_ttl_expiry']) {
    for (const clock of [59_000, 60_000]) {
      const otp = resolveReplayVariables({ baseUrl: target, now: clock, definitions: {
        OTP: { kind: 'totp', value: seed, refresh: policy, ttl_seconds: 1, updated_at: '1970-01-01T00:00:00Z' },
      } });
      assert.equal(otp.values.OTP, generateTotp(seed, clock));
      assert.equal(otp.diagnostics[0].status, 'resolved');
    }
  }
  console.log('PASS TOTP regenerates at the current time across code rollover instead of expiring its seed definition');

  function tracePart(label, text) {
    const bytes = Buffer.from(text);
    const lines = [`${label}, ${bytes.length} bytes (0x${bytes.length.toString(16)})`];
    for (let offset = 0; offset < bytes.length; offset += 16) {
      const hex = [...bytes.subarray(offset, offset + 16)].map((byte) => byte.toString(16).padStart(2, '0')).join(' ');
      lines.push(`${offset.toString(16).padStart(4, '0')}: ${hex.padEnd(47)} fixture`);
    }
    return lines.join('\n');
  }
  const captured = async (token, capturedAt, exitCode = 0) => persistCapturedTrace({
    deliverablesDir: dir, findingId: 'AUTH-01', capturedAt, exitCode,
    trace: [
      tracePart('=> Send header', 'GET /login HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n'),
      tracePart('<= Recv header', 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'),
      tracePart('<= Recv data', `{\n\n"data":{"token":"${token}"}}`),
    ].join('\n'),
  });
  const timestamp = Date.now();
  await captured('current-response', new Date(timestamp).toISOString());
  // Written later, but captured earlier: filenames must not determine source freshness.
  await captured('stale-response', new Date(timestamp - 120_000).toISOString());
  await captured('failed-transfer', new Date(timestamp + 1000).toISOString(), 1);
  const responses = await loadReplayResponses(dir);
  assert.equal(responses.responseBodies.get('AUTH-01').data.token, 'current-response');
  assert.equal(responses.responseCapturedAt.get('AUTH-01'), timestamp);
  console.log('PASS response loading chooses actual capture time, ignores failed transfers and preserves JSON with blank lines');

  const privateDir = `${temporary}/private`;
  await mkdir(privateDir);
  await writeFile(`${privateDir}/AUTH-02.json`, JSON.stringify({ ...refresh('each_attempt'), OLD_TOKEN: expired }), { mode: 0o600 });
  const definitions = await loadReplayVariableDefinitions(privateDir, 'AUTH-02');
  const exploitCollector = createExploitCollector({
    vulnClass: 'auth', validIds: new Set(['AUTH-02', 'AUTH-03']),
    validateReplayVariables: async (findingId, httpPlan, savedBrowserPlan) => {
      const names = missingReplayVariables(httpPlan,
        await loadReplayVariableDefinitions(privateDir, findingId), [], savedBrowserPlan);
      return names.length ? `Missing: ${names.join(', ')}` : undefined;
    },
  });
  const exploit = (id) => ({
    status: 'exploited', vulnerability_id: id, title: 'Protected record access',
    vulnerable_location: '/proof', overview: 'Fixture', severity: 'high', severity_rationale: 'Fixture',
    impact: 'Reads protected record', exploitation_steps: ['Read record'], proof_of_impact: 'protected-record',
    http_replay: plan('?token=${TOKEN}'),
  });
  const submit = async (id) => JSON.parse((await exploitCollector.tools[0].execute(id, exploit(id))).content[0].text);
  assert.equal((await submit('AUTH-02')).status, 'success');
  const rejected = await submit('AUTH-03');
  assert.equal(rejected.status, 'error');
  assert.match(rejected.message, /TOKEN/);
  assert.deepEqual(missingReplayVariables(plan(), {}, [], browserPlan), ['BROWSER_INPUT']);
  assert.deepEqual(missingReplayVariables(plan(), { BROWSER_INPUT: definitions.TOKEN }, [], browserPlan), []);
  assert.equal((await resolve('AUTH-02', definitions, { httpPlan: plan('?token=${TOKEN}') })).values.TOKEN, 'current-response');
  assert.equal((await resolve('AUTH-03', { TOKEN: { kind: 'response_extract', source_finding: 'AUTH-99', pointer: 'missing' } }, {
    httpPlan: plan('?token=${TOKEN}'),
  })).diagnostics[0].status, 'extract_failed', 'Accepting a refresh definition never waives runtime resolution');
  console.log('PASS Exploit accepts structured refresh contracts, rejects absent inputs and Record resolves the source at execution time');

  const retryDir = `${temporary}/retry`;
  await updateReplayVariables(retryDir, 'AUTH-02', plan('?token=${TOKEN}'), { TOKEN: 'observed-new-value' }, [], {
    TOKEN: expired, OLD_TOKEN: expired,
  });
  const repaired = await loadReplayVariableDefinitions(retryDir, 'AUTH-02');
  const afterRepair = await resolve('AUTH-02', repaired, { httpPlan: plan('?token=${TOKEN}') });
  assert.equal(afterRepair.values.TOKEN, 'observed-new-value');
  assert.equal(afterRepair.diagnostics.every((item) => item.status === 'resolved'), true);
  assert.equal((await stat(`${retryDir}/AUTH-02.json`)).mode & 0o777, 0o600);
  assert.equal((await readFile(`${privateDir}/AUTH-02.json`, 'utf8')).includes('observed-new-value'), false);
  console.log('PASS retry repairs the required static input privately while an obsolete expired variable remains harmless');
} finally {
  await rm(temporary, { recursive: true, force: true });
}
