import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { validateRecordTarget } from '../apps/worker/dist/collectors/record-collector.js';
import {
  candidateMatchesExploreSearch,
  locationMatchesExploreSearch,
  searchExploreTemplates,
} from '../apps/worker/dist/services/explore-search.js';

const target = 'https://example.test';
validateRecordTarget(['-H', 'X-Test: https://other.test', '--url', `${target}/x`], target);
for (const args of [
  [`${target}/x`, 'https://other.test/'],
  [`${target}/x`, '--location'],
  [`${target}/x`, '--url=https://other.test/'],
  [`${target}/{a,b}`],
  ['--config', 'file', `${target}/x`],
]) assert.throws(() => validateRecordTarget(args, target));

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
  await writeFile(path.join(dir, 'seed.js'), `${'danger()\n'.repeat(10)}danger()\n`);
  await writeFile(path.join(dir, 'other.js'), 'danger()\n'.repeat(50));
  const result = await searchExploreTemplates(dir, [{
    finding_id: 'F-1', vulnerability_class: 'xss', sink_file: 'seed.js', sink_line: 11,
    regex: 'danger\\(\\)', rationale: 'test',
  }]);
  assert.equal(result.rejected.length, 0, 'seed after eighth match must be accepted');
  assert.equal(result.truncated, true, 'bounded results must disclose truncation');
  assert.equal(result.matches.length, 40);
} finally {
  await rm(dir, { recursive: true, force: true });
}
