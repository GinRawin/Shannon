import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createExploitReviewCollector } from '../apps/worker/dist/collectors/exploit-review-collector.js';
import { validateRecordTarget } from '../apps/worker/dist/collectors/record-collector.js';
import {
  applyExploitReviews,
  mergeRecordVerdicts,
  validateRecordBrowserEvidence,
} from '../apps/worker/dist/services/record-verification.js';
import {
  generateTotp,
  loadReplayVariableDefinitions,
  missingReplayVariables,
  resolveReplayVariables,
  updateReplayVariables,
} from '../apps/worker/dist/services/replay-variables.js';
import {
  candidateMatchesExploreSearch,
  locationMatchesExploreSearch,
  searchExploreTemplates,
} from '../apps/worker/dist/services/explore-search.js';

const target = 'https://example.test';
validateRecordTarget(['-H', 'X-Test: https://other.test', '--url', `${target}/x`], target);
validateRecordTarget(['-skS', '-H', 'X-Test: fixture', `${target}/x`], target);
validateRecordTarget(['-sSHX-Test: https://other.test', `${target}/x`], target);
validateRecordTarget(['-skX', 'POST', '-d', 'https://other.test', `${target}/x`], target);
for (const args of [
  [`${target}/x`, 'https://other.test/'],
  [`${target}/x`, '--location'],
  [`${target}/x`, '--url=https://other.test/'],
  [`${target}/{a,b}`],
  ['--config', 'file', `${target}/x`],
  ['-skL', `${target}/x`],
  ['-skK', 'file', `${target}/x`],
  ['-sSX'],
  ['-', `${target}/x`],
]) assert.throws(() => validateRecordTarget(args, target));

const baseVerdict = {
  finding_id: 'AUTH-01', reason: 'fixture', capture_ids: [], frontend_status: 'unable_to_determine',
  frontend_url: null, frontend_trigger: null, frontend_reason: 'fixture', stage: 'record',
};
assert.equal(
  mergeRecordVerdicts(
    [{ ...baseVerdict, status: 'verified' }],
    [{ ...baseVerdict, status: 'failed', reason: 'later failure' }],
  )[0].status,
  'verified',
  'a later failure must not downgrade a verified finding',
);
assert.equal(
  mergeRecordVerdicts(
    [{ ...baseVerdict, status: 'failed' }],
    [{ ...baseVerdict, status: 'verified', stage: 'record-retry' }],
  )[0].status,
  'verified',
  'a successful retry must replace the prior failed verdict by finding ID',
);
assert.equal(generateTotp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59_000), '287082');
const variableResolution = resolveReplayVariables({
  baseUrl: 'https://example.test/path',
  now: Date.parse('2026-01-01T00:10:00Z'),
  responseBodies: new Map([['AUTH-01', { data: { token: 'fresh-token' } }]]),
  definitions: {
    LEGACY: 'legacy-value',
    TOKEN: { kind: 'response_extract', source_finding: 'AUTH-01', pointer: 'data.token' },
    EXPIRED: { kind: 'static', value: 'old', ttl_seconds: 60, updated_at: '2026-01-01T00:00:00Z' },
  },
});
assert.equal(variableResolution.values.BASE_URL, 'https://example.test');
assert.equal(variableResolution.values.LEGACY, 'legacy-value');
assert.equal(variableResolution.values.TOKEN, 'fresh-token');
assert.equal(variableResolution.diagnostics.find((item) => item.name === 'EXPIRED').status, 'expired');
assert.deepEqual(
  missingReplayVariables({ steps: [{ method: 'GET', url: '${BASE_URL}/x?token=${TOKEN}', expect: { status: 200, body_contains: 'ok' } }] }, { TOKEN: 'set' }),
  [],
  'BASE_URL is always host supplied and must use the same availability rule as the loader',
);

const retryPlan = {
  steps: [{
    method: 'GET',
    url: '${BASE_URL}/retry?legacy=${LEGACY}&fresh=${FRESH}',
    expect: { status: 200, body_contains: 'ok' },
  }],
};
const reviewCollector = createExploitReviewCollector(new Set(['AUTH-01']));
const reviewTool = reviewCollector.tools[0];
const reviewResult = async (input) => JSON.parse((await reviewTool.execute('review', input)).content[0].text);
for (const [input, expected] of [
  [{ finding_id: 'AUTH-01', verdict: 'retry', reason: 'fixture' }, 'revised_http_replay'],
  [{ finding_id: 'AUTH-01', verdict: 'retry', reason: 'fixture', revised_http_replay: retryPlan }, 'variable_requirements'],
  [{
    finding_id: 'AUTH-01', verdict: 'retry', reason: 'fixture', revised_http_replay: retryPlan,
    variable_requirements: {},
  }, 'record_instructions'],
  [{
    finding_id: 'AUTH-01', verdict: 'retry', reason: 'fixture', revised_http_replay: retryPlan,
    variable_requirements: {}, record_instructions: ['Replay with refreshed values.'],
  }, 'expected_evidence'],
]) {
  const result = await reviewResult(input);
  assert.equal(result.status, 'error');
  assert.match(result.message, new RegExp(expected));
}
assert.equal((await reviewResult({
  finding_id: 'AUTH-01', verdict: 'retry', reason: 'The saved token expired.', revised_http_replay: retryPlan,
  variable_requirements: { FRESH: { refresh: 'each_attempt' } },
  record_instructions: ['Refresh FRESH before replay.'],
  expected_evidence: { http_packet: true },
})).status, 'success');
assert.deepEqual(reviewCollector.getAll()[0].record_instructions, ['Refresh FRESH before replay.']);
console.log('PASS retry reviews require the revised plan, variable contract, instructions, and expected evidence');

const exploreMatches = [
  { match_file: 'src/query.ts', match_line: 42 },
  { match_file: 'src/query.ts', match_line: 80 },
];
assert.equal(
  locationMatchesExploreSearch({ file: 'src/query.ts', start_line: 40, end_line: 45 }, exploreMatches),
  true,
  'an exact Explore hit inside the submitted range must bind the location',
);
assert.equal(
  locationMatchesExploreSearch({ file: 'src/query.ts', start_line: 41 }, exploreMatches),
  false,
  'matching only the file must not bind the location',
);
assert.equal(
  candidateMatchesExploreSearch({
    code_locations: [{ file: 'src/query.ts', start_line: 42, role: 'sink' }],
  }, exploreMatches),
  true,
  'an independent candidate must bind an exact Explore hit as a sink',
);
for (const candidate of [
  { code_locations: [{ file: 'src/query.ts', start_line: 42, role: 'source' }] },
  { code_locations: [{ file: 'src/query.ts', start_line: 43, role: 'sink' }] },
  { code_locations: [{ file: 'src/other.ts', start_line: 42, role: 'sink' }] },
  { code_locations: [{ file: 'src/query.ts', role: 'sink' }] },
]) {
  assert.equal(
    candidateMatchesExploreSearch(candidate, exploreMatches),
    false,
    'unbound independent candidates must be rejected',
  );
}

const dir = await mkdtemp(path.join(tmpdir(), 'shannon-explore-test-'));
try {
  const initialVariables = path.join(dir, 'variables', 'initial');
  const retryVariables = path.join(dir, 'variables', 'retry');
  await mkdir(initialVariables, { recursive: true });
  await writeFile(path.join(initialVariables, 'AUTH-01.json'), JSON.stringify({
    LEGACY: 'inherited-value',
    TOKEN: { kind: 'response_extract', source_finding: 'AUTH-02', pointer: 'data.token' },
  }));
  const baseline = await loadReplayVariableDefinitions(initialVariables, 'AUTH-01');
  assert.deepEqual(
    await updateReplayVariables(retryVariables, 'AUTH-01', retryPlan, { FRESH: 'new-value' }, [], baseline),
    ['FRESH'],
  );
  assert.deepEqual(await loadReplayVariableDefinitions(retryVariables, 'AUTH-01'), {
    LEGACY: 'inherited-value',
    TOKEN: { kind: 'response_extract', source_finding: 'AUTH-02', pointer: 'data.token' },
    FRESH: 'new-value',
  });
  console.log('PASS retry variable repair inherits prior private definitions without flattening structured values');

  const scratchpad = path.join(dir, '.shannon', 'scratchpad');
  await mkdir(scratchpad, { recursive: true });
  await writeFile(path.join(scratchpad, 'stale.png'), 'stale');
  await writeFile(path.join(scratchpad, 'fresh.png'), 'fresh');
  const retryStarted = Date.now();
  await utimes(path.join(scratchpad, 'stale.png'), (retryStarted - 5000) / 1000, (retryStarted - 5000) / 1000);
  await utimes(path.join(scratchpad, 'fresh.png'), (retryStarted + 1000) / 1000, (retryStarted + 1000) / 1000);
  await assert.rejects(
    validateRecordBrowserEvidence(dir, ['.shannon/scratchpad/stale.png'], retryStarted),
    /predates this Record retry attempt/,
  );
  assert.deepEqual(
    await validateRecordBrowserEvidence(dir, ['.shannon/scratchpad/fresh.png'], retryStarted),
    ['.shannon/scratchpad/fresh.png'],
  );
  console.log('PASS Record retry rejects stale XSS screenshots and accepts evidence created for this attempt');

  await writeFile(path.join(dir, 'seed.js'), `${'danger()\n'.repeat(10)}danger()\n`);
  await writeFile(path.join(dir, 'other.js'), 'danger()\n'.repeat(50));
  const result = await searchExploreTemplates(dir, [{
    finding_id: 'F-1', vulnerability_class: 'xss', sink_file: 'seed.js', sink_line: 11,
    regex: 'danger\\(\\)', rationale: 'test',
  }]);
  assert.equal(result.rejected.length, 0, 'seed after eighth match must be accepted');
  assert.equal(result.truncated, true, 'bounded results must disclose truncation');
  assert.equal(result.matches.length, 40);
  assert.deepEqual(result.templates, [{
    finding_id: 'F-1',
    vulnerability_class: 'xss',
    sink_file: 'seed.js',
    sink_line: 11,
    regex: 'danger\\(\\)',
    total_hits: 61,
    excluded_seed: 1,
    duplicate_hits: 0,
    returned_hits: 40,
    truncated: true,
  }], 'per-template accounting must explain where hits went');

  await writeFile(path.join(dir, 'broad.js'), 'broad()\n'.repeat(41));
  await writeFile(path.join(dir, 'narrow.js'), 'narrow()\n'.repeat(3));
  const interleaved = await searchExploreTemplates(dir, [
    {
      finding_id: 'BROAD-1', vulnerability_class: 'injection', sink_file: 'broad.js', sink_line: 41,
      regex: 'broad\\(\\)', rationale: 'test',
    },
    {
      finding_id: 'NARROW-1', vulnerability_class: 'injection', sink_file: 'narrow.js', sink_line: 3,
      regex: 'narrow\\(\\)', rationale: 'test',
    },
  ]);
  assert.equal(interleaved.truncated, false);
  assert.deepEqual(
    interleaved.matches.slice(0, 4).map((match) => match.finding_id),
    ['BROAD-1', 'NARROW-1', 'BROAD-1', 'NARROW-1'],
    'templates must be interleaved so an early broad template cannot starve a later narrow one',
  );
  assert.ok(
    interleaved.matches.some((match) => match.finding_id === 'NARROW-1' && match.match_line === 1),
    'the narrow template must contribute its own discoveries',
  );
  console.log('PASS Explore search reports per-template accounting and interleaves broad and narrow templates');

  const fp = { status: 'exploited', vulnerability_id: 'INJ-02', title: 'False positive fixture' };
  const retained = { status: 'exploited', vulnerability_id: 'INJ-03', title: 'Retained fixture' };
  await writeFile(path.join(dir, 'injection_exploit_collector.json'), JSON.stringify([fp, retained]));
  await writeFile(path.join(dir, 'injection_exploit_collector_renumbered.json'), JSON.stringify([
    { ...fp, vulnerability_id: 'INJ-01' }, { ...retained, vulnerability_id: 'INJ-02' },
  ]));
  await writeFile(path.join(dir, 'injection_renumber_map.json'), JSON.stringify({ map: { 'INJ-02': 'INJ-01', 'INJ-03': 'INJ-02' } }));
  await writeFile(path.join(dir, 'injection_exploitation_queue.json'), JSON.stringify({ vulnerabilities: [{ ID: 'INJ-02' }, { ID: 'INJ-03' }] }));
  await writeFile(path.join(dir, 'record_verification.json'), JSON.stringify([
    { ...baseVerdict, finding_id: 'INJ-02', status: 'failed' },
    { ...baseVerdict, finding_id: 'INJ-03', status: 'verified' },
  ]));
  await writeFile(path.join(dir, 'record_verified_finding_ids.json'), JSON.stringify(['INJ-01', 'INJ-02']));
  await applyExploitReviews(dir, [{ finding_id: 'INJ-02', verdict: 'false_positive', reason: 'fixture evidence' }]);
  const sourceAfterReview = JSON.parse(await readFile(path.join(dir, 'injection_exploit_collector.json'), 'utf8'));
  const renumberedAfterReview = JSON.parse(await readFile(path.join(dir, 'injection_exploit_collector_renumbered.json'), 'utf8'));
  assert.deepEqual(sourceAfterReview.map((entry) => entry.vulnerability_id), ['INJ-03']);
  assert.deepEqual(renumberedAfterReview.map((entry) => entry.vulnerability_id), ['INJ-02']);
  assert.deepEqual(JSON.parse(await readFile(path.join(dir, 'injection_renumber_map.json'), 'utf8')).map, { 'INJ-03': 'INJ-02' });
  assert.deepEqual(JSON.parse(await readFile(path.join(dir, 'record_verified_finding_ids.json'), 'utf8')), ['INJ-02']);
} finally {
  await rm(dir, { recursive: true, force: true });
}
