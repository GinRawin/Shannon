/**
 * Offline fixture test for the Explore v3 AST structural clone retrieval.
 *
 * Run `pnpm --filter @shannon/worker build` first, then:
 *   node scripts/test-explore-ast-clone-search.mjs
 *
 * The fixture repository lives under scripts/fixtures/explore-ast/repo and is copied into a
 * temporary directory so the symlink path-escape case can be created safely. Every assertion maps
 * onto the acceptance cases T01-T19 in shannon_explore_ast_implementation.md.
 */
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { searchAstCloneCandidates } from '../apps/worker/dist/services/explore-ast-clone-search.js';
import { locationMatchesExploreSearch } from '../apps/worker/dist/services/explore-search.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = path.join(repoRoot, 'scripts', 'fixtures', 'explore-ast', 'repo');
const dir = await mkdtemp(path.join(tmpdir(), 'shannon-ast-test-'));
const outsideDir = `${dir}-outside`;

async function lineOf(relative, needle) {
  const text = await readFile(path.join(dir, relative), 'utf8');
  const index = text.split('\n').findIndex((line) => line.includes(needle));
  assert.ok(index >= 0, `fixture ${relative} must contain ${needle}`);
  return index + 1;
}

const find = (matches, file) => matches.find((match) => match.match_file === file);
const inRange = (match) =>
  match.candidate_start_line <= match.match_line && match.match_line <= match.candidate_end_line;

try {
  await cp(fixtures, dir, { recursive: true });
  await mkdir(outsideDir, { recursive: true });
  await writeFile(path.join(outsideDir, 'escape.ts'), 'export const leaked = 1;\n');
  await symlink(path.join(outsideDir, 'escape.ts'), path.join(dir, 'src', 'escape.ts'));

  // --- T01/T02/T03/T04/T05/T17: Type-1/2/3 retrieval from a TypeScript seed ---------------
  const seedLine = await lineOf('src/orders.ts', 'SELECT id, total FROM orders');
  const documentLine = await lineOf('src/documents.ts', 'SELECT id, title FROM documents');
  const formattedLine = await lineOf('src/formatted.ts', 'const order = await pool.query(');
  const ticketLine = await lineOf('src/tickets.ts', 'SELECT id, subject FROM tickets');
  const reportLine = await lineOf('src/reports.ts', 'SELECT id, body FROM reports');
  const adminLine = await lineOf('src/admin.ts', 'SELECT id, total FROM orders');

  const seeds = [{ findingId: 'INJ-01', vulnerabilityClass: 'injection', file: 'src/orders.ts', line: seedLine }];
  const outcome = await searchAstCloneCandidates(dir, seeds);
  const matches = outcome.result.matches;

  assert.equal(outcome.result.schema_version, 3, 'v3 result must advertise schema_version 3');
  assert.equal(outcome.result.algorithm, 'ast_structural_clone_v1', 'v3 result must advertise the AST algorithm');
  assert.equal(outcome.result.truncated, false, 'a small fixture repository must not truncate');
  assert.equal(outcome.result.statistics.seed_count, 1);
  assert.equal(outcome.result.statistics.eligible_seed_count, 1);
  assert.equal(outcome.result.statistics.candidate_count, matches.length, 'statistics must count the returned matches');
  for (const match of matches) {
    assert.equal(match.finding_id, 'INJ-01');
    assert.equal(match.vulnerability_class, 'injection');
    assert.equal(match.seed_file, 'src/orders.ts');
    assert.equal(match.seed_line, seedLine);
    assert.ok(inRange(match), `${match.match_file}:${match.match_line} must lie inside its candidate range`);
    assert.ok(match.ast_evidence.anchor_mapped, 'only anchor-mapped candidates are reported as matches');
    assert.ok(match.excerpt.trim().length > 0, 'the excerpt must come from the real candidate line');
    assert.ok(!match.excerpt.includes(match.match_file), 'the excerpt must not embed the file path');
  }

  const cloned = find(matches, 'src/documents.ts');
  assert.ok(cloned, 'the Type-2 rename/literal clone must be retrieved');
  assert.equal(cloned.match_line, documentLine, 'match_line must be the real statement line of the clone');
  assert.ok(cloned.score >= 0.99, `Type-2 clone score ${cloned.score} should be near 1.0`);
  assert.equal(cloned.ast_evidence.tree_similarity, 1, 'a rename-only clone must map almost every AST node');

  const typeOne = find(matches, 'src/formatted.ts');
  assert.ok(typeOne, 'the Type-1 reformatted/comment clone must be retrieved');
  assert.equal(typeOne.match_line, formattedLine, 'the Type-1 clone match_line must be the real statement line');
  assert.ok(typeOne.score >= 0.99, `Type-1 clone score ${typeOne.score} should stay near 1.0`);

  const inserted = find(matches, 'src/tickets.ts');
  assert.ok(inserted, 'the Type-3 logger-insertion clone must be retrieved');
  assert.equal(inserted.match_line, ticketLine);
  assert.ok(inserted.ast_evidence.inserted_subtrees >= 1, 'T03 must report the inserted logger statement subtree');

  const edited = find(matches, 'src/reports.ts');
  assert.ok(edited, 'the Type-3 insertion/deletion clone must be retrieved');
  assert.equal(edited.match_line, reportLine);
  assert.ok(edited.ast_evidence.deleted_subtrees >= 1, 'T05 must report the deleted assignment subtree');
  assert.ok(edited.score < cloned.score, `Type-3 score ${edited.score} must sit below the Type-2 score`);

  const safe = find(matches, 'src/admin.ts');
  assert.ok(safe, 'a safe clone with an extra authorization check is still a structural candidate');
  assert.equal(safe.match_line, adminLine);
  assert.ok(safe.ast_evidence.inserted_subtrees >= 1, 'T04 must report the inserted guard/error subtree');

  assert.equal(
    matches.some((match) => match.match_file === 'src/orders.ts' && match.match_line === seedLine),
    false,
    'the seed statement itself must not be returned as a new match',
  );
  for (const match of matches) assert.ok(inRange(match));
  console.log('PASS T01-T05/T17 Type-1/2/3 retrieval, subtree edits, safe clone, and real match_line');

  // Scores are reported in a stable descending order (T16) and the run is deterministic (T16/T19).
  const scores = matches.map((match) => match.score);
  assert.deepEqual(scores, [...scores].sort((left, right) => right - left), 'matches must be ranked by score');
  const repeat = await searchAstCloneCandidates(dir, seeds);
  assert.equal(
    JSON.stringify(repeat.result),
    JSON.stringify(outcome.result),
    'identical input must produce byte-identical results (determinism / resume safety)',
  );
  console.log('PASS T16/T19 stable ranking and byte-identical repeat runs');

  // --- T06: same node counts but different parent/child structure ------------------------
  const shapeLine = await lineOf('src/shape_base.ts', 'SELECT id FROM shapes');
  const shapeSameLine = await lineOf('src/shape_same.ts', 'const left = await pool.query(');
  const shapeDiffLine = await lineOf('src/shape_diff.ts', 'const first = await pool.query(');
  const shapeOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'SH-01', vulnerabilityClass: 'authz', file: 'src/shape_base.ts', line: shapeLine },
  ]);
  const shapeSame = find(shapeOutcome.result.matches, 'src/shape_same.ts');
  const shapeDiff = find(shapeOutcome.result.matches, 'src/shape_diff.ts');
  assert.ok(shapeSame, 'the structurally identical rename clone must be retrieved');
  assert.equal(shapeSame.match_line, shapeSameLine);
  assert.ok(shapeSame.score >= 0.99, `identical structure must score near 1.0 (got ${shapeSame.score})`);
  assert.ok(shapeDiff, 'the structure-different variant must still be recalled');
  assert.equal(shapeDiff.match_line, shapeDiffLine);
  assert.ok(shapeDiff.score < 0.95, `T06: structure-different score ${shapeDiff.score} must not look identical`);
  assert.ok(
    shapeSame.score - shapeDiff.score >= 0.1,
    `T06: structure difference must reduce the score (${shapeSame.score} vs ${shapeDiff.score})`,
  );
  console.log('PASS T06 identical node counts with different parent/child structure score lower');

  // --- T07: control-context change (call inside vs outside the guard) --------------------
  const guardLine = await lineOf('src/ctx_a.ts', 'SELECT id FROM guarded');
  const movedCallLine = await lineOf('src/ctx_b.ts', 'SELECT id FROM guarded');
  const guardOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'C-01', vulnerabilityClass: 'authz', file: 'src/ctx_a.ts', line: guardLine },
  ]);
  const movedCall = guardOutcome.result.matches.find(
    (match) => match.match_file === 'src/ctx_b.ts' && match.match_line === movedCallLine,
  );
  assert.ok(movedCall, 'the call moved out of the guard block must map to its real line');
  assert.equal(movedCall.ast_evidence.control_context_changed, true, 'T07 must flag the changed control context');
  assert.equal(movedCall.ast_evidence.anchor_mapped, true, 'the seed anchor must map onto the moved call');
  console.log('PASS T07 control-context change is recorded and the anchor maps to the moved call');

  // --- T08: one line, multiple calls -> several anchors, never a guessed sink ------------
  const multiLine = await lineOf('src/multi.ts', 'audit(');
  const multiOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'M-01', vulnerabilityClass: 'injection', file: 'src/multi.ts', line: multiLine },
  ]);
  const multiSeed = multiOutcome.seeds.seeds.find((record) => record.finding_id === 'M-01');
  assert.ok(multiSeed, 'the multi-statement seed must be recorded');
  assert.equal(multiSeed.status, 'eligible');
  assert.ok(multiSeed.anchor_candidates >= 2, 'a one-line multi-statement seed must expose several anchors');
  assert.ok(
    multiOutcome.result.statistics.ambiguous_anchors >= 1,
    'multiple anchor statements on the recorded line must be counted as ambiguous',
  );
  for (const match of multiOutcome.result.matches) {
    assert.ok(match.ast_evidence.anchor_mapped, 'every reported match must have a mapped anchor (no guessed sink)');
    assert.ok(inRange(match));
  }
  console.log('PASS T08 multi-anchor ambiguity is reported without guessing a single sink');

  // --- T09: nested function call never crosses the function boundary ---------------------
  const nestedLine = await lineOf('src/nested.ts', 'SELECT id, total FROM orders');
  const nestedHeadLine = await lineOf('src/nested.ts', 'export function makeLoader');
  const nestedOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'D-01', vulnerabilityClass: 'injection', file: 'src/nested.ts', line: nestedLine },
  ]);
  for (const match of nestedOutcome.result.matches) {
    assert.notEqual(match.match_line, nestedHeadLine, 'match_line must not fall back to a candidate function head');
    assert.ok(inRange(match), 'nested matches must stay within their own candidate range');
  }
  console.log('PASS T09 nested call context stays inside its enclosing function');

  // --- T10: parse error / missing / unsupported / out-of-range are distinct skip reasons --
  const skipOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'B-01', vulnerabilityClass: 'injection', file: 'src/broken.ts', line: 1 },
    { findingId: 'B-02', vulnerabilityClass: 'injection', file: 'src/ghost.ts', line: 1 },
    { findingId: 'B-03', vulnerabilityClass: 'injection', file: 'src/legacy.py', line: 2 },
    { findingId: 'B-04', vulnerabilityClass: 'injection', file: 'src/orders.ts', line: 99_999 },
    { findingId: 'B-05', vulnerabilityClass: 'injection', file: 'src/escape.ts', line: 1 },
    { findingId: 'B-06', vulnerabilityClass: 'injection', file: 'src/orders.ts', line: 0 },
  ]);
  const reasons = new Map(skipOutcome.result.skipped_seeds.map((record) => [record.finding_id, record.reason]));
  assert.equal(reasons.get('B-01'), 'parse_error', 'a syntax-error file must be skipped as parse_error');
  assert.equal(reasons.get('B-02'), 'seed_file_missing');
  assert.equal(reasons.get('B-03'), 'unsupported_language');
  assert.equal(reasons.get('B-04'), 'anchor_not_found', 'an out-of-range recorded line must not fabricate a match');
  assert.equal(reasons.get('B-05'), 'seed_path_outside_repository', 'a symlink escaping the repo must be rejected');
  assert.equal(reasons.get('B-06'), 'invalid_seed_line');
  assert.equal(skipOutcome.result.statistics.eligible_seed_count, 0);
  assert.ok(skipOutcome.result.statistics.parse_failed_files >= 1, 'parse failures are counted separately from zero matches');
  assert.ok(skipOutcome.result.statistics.parser_language_unsupported >= 1);
  assert.deepEqual(skipOutcome.result.matches, []);
  console.log('PASS T10/T14 parse error, missing, unsupported, out-of-range, and symlink escape skip reasons');

  // --- T11: a similar implementation elsewhere in the same file is returned, seed excluded
  const leftLine = await lineOf('src/repeat.ts', 'left_table');
  const rightLine = await lineOf('src/repeat.ts', 'right_table');
  const sameFileOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'R-01', vulnerabilityClass: 'injection', file: 'src/repeat.ts', line: leftLine },
  ]);
  const twin = find(sameFileOutcome.result.matches, 'src/repeat.ts');
  assert.ok(twin, 'the twin implementation in the same file must be retrieved');
  assert.equal(twin.match_line, rightLine, 'the twin match_line must point at its own statement');
  assert.ok(
    sameFileOutcome.result.matches.every((match) => !(match.match_file === 'src/repeat.ts' && match.match_line === leftLine)),
    'the seed statement must never be returned as its own clone',
  );
  console.log('PASS T11 same-file twin is retrieved while the seed location is excluded');

  // --- T12: same-language only (Java seed never reads the JS/TS side) --------------------
  const javaSeedLine = await lineOf('src/OrderDao.java', 'statement.executeQuery(sql)');
  const javaDocumentLine = await lineOf('src/DocumentDao.java', 'stmt.executeQuery(query)');
  const javaTicketLine = await lineOf('src/TicketDao.java', 'statement.executeQuery(sql)');
  const javaSeeds = [
    { findingId: 'JINJ-01', vulnerabilityClass: 'injection', file: 'src/OrderDao.java', line: javaSeedLine },
    { findingId: 'JINJ-02', vulnerabilityClass: 'injection', file: 'src/legacy.py', line: 2 },
  ];
  const javaOutcome = await searchAstCloneCandidates(dir, javaSeeds);
  const javaMatches = javaOutcome.result.matches;
  const javaFind = (file) => find(javaMatches, file);
  const javaSourceCount = (await readdir(path.join(dir, 'src'))).filter((name) => name.endsWith('.java')).length;
  assert.equal(
    javaOutcome.coverage.summary.indexed_files,
    javaSourceCount,
    'a Java-only seed must index exactly the Java sources and skip the JavaScript/TypeScript side',
  );
  assert.equal(
    javaOutcome.result.skipped_seeds.find((record) => record.finding_id === 'JINJ-02').reason,
    'unsupported_language',
    'a non JS/TS/Java seed is still reported as unsupported_language',
  );
  const javaCloned = javaFind('src/DocumentDao.java');
  assert.ok(javaCloned, 'the Java Type-2 clone must be retrieved');
  assert.equal(javaCloned.match_line, javaDocumentLine);
  assert.ok(javaCloned.score >= 0.99, `Java Type-2 clone score ${javaCloned.score} should be near 1.0`);
  assert.ok(javaFind('src/TicketDao.java'), 'the Java Type-3 insertion clone must be retrieved');
  assert.equal(javaFind('src/TicketDao.java').match_line, javaTicketLine);
  assert.equal(javaFind('src/documents.ts'), undefined, 'a Java-only seed must never return a JS/TS clone');
  assert.ok(javaMatches.every((match) => match.match_file.endsWith('.java')), 'Java matches stay in Java files');
  assert.equal(javaFind('src/OrderDao.java'), undefined, 'the Java seed location must not be returned as a match');
  console.log('PASS T12 Java Type-2/Type-3 retrieval and JS/TS language isolation');

  // A JS/TS seed, symmetrically, must never return a Java candidate.
  assert.ok(matches.every((match) => !match.match_file.endsWith('.java')), 'a TS seed must not return Java clones');

  // --- T15: Unicode, multi-line call, and CRLF all keep accurate byte/line ranges --------
  const unicodeLine = await lineOf('src/unicode.ts', 'SELECT id, total FROM orders');
  const unicodeOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'U-01', vulnerabilityClass: 'injection', file: 'src/unicode.ts', line: unicodeLine },
  ]);
  const unicodeSeed = unicodeOutcome.seeds.seeds.find((record) => record.finding_id === 'U-01');
  assert.equal(unicodeSeed.status, 'eligible', 'a Unicode identifier / multi-line call seed must parse cleanly');
  assert.ok(unicodeOutcome.result.matches.length >= 1, 'a Unicode seed must still retrieve structural clones');
  for (const match of unicodeOutcome.result.matches) {
    assert.ok(inRange(match), 'Unicode/CRLF candidates must keep a 1-based line inside their range');
    assert.ok(match.excerpt.length <= 800, 'the excerpt must stay inside the configured budget');
  }
  const crlfLine = await lineOf('src/crlf.ts', 'SELECT id, body FROM notes');
  const crlfOutcome = await searchAstCloneCandidates(dir, [
    { findingId: 'CR-01', vulnerabilityClass: 'injection', file: 'src/crlf.ts', line: crlfLine },
  ]);
  const crlfMatch = find(crlfOutcome.result.matches, 'src/structure_a.ts');
  assert.ok(crlfMatch, 'a CRLF file must parse and still match a same-structure clone');
  assert.equal(crlfMatch.match_line, await lineOf('src/structure_a.ts', 'SELECT id FROM things'));
  console.log('PASS T15 Unicode identifiers, multi-line calls, and CRLF keep accurate 1-based lines');

  // --- T13: budgets are enforced and disclosed ------------------------------------------
  const bounded = await searchAstCloneCandidates(dir, seeds, { maxTotalMatches: 1 });
  assert.equal(bounded.result.matches.length, 1, 'the global match cap must be enforced');
  assert.equal(bounded.result.truncated, true, 'hitting the global match cap must disclose truncation');
  const seedLimited = await searchAstCloneCandidates(dir, [
    ...seeds,
    { findingId: 'INJ-02', vulnerabilityClass: 'injection', file: 'src/documents.ts', line: documentLine },
  ], { maxSeeds: 1 });
  assert.equal(seedLimited.result.skipped_seeds.find((record) => record.finding_id === 'INJ-02').reason, 'seed_limit');
  assert.equal(seedLimited.result.truncated, true, 'the seed cap must disclose truncation');
  const shortForest = await searchAstCloneCandidates(dir, seeds, { minForestNodes: 10_000 });
  assert.equal(shortForest.result.statistics.eligible_seed_count, 0);
  assert.equal(
    shortForest.result.skipped_seeds[0].reason,
    'forest_too_small',
    'a too-strict node budget must be reported, never silently swallowed',
  );
  console.log('PASS T13 match/seed/node budgets are enforced and disclosed as truncation or skip reasons');

  // --- T18: downstream Expansion admission binds the exact clone line -------------------
  assert.equal(
    locationMatchesExploreSearch({ file: cloned.match_file, start_line: cloned.match_line, role: 'sink' }, matches),
    true,
    'a sink location covering the clone match line must be admitted downstream',
  );
  assert.equal(
    locationMatchesExploreSearch({ file: cloned.match_file, start_line: documentLine + 40, role: 'sink' }, matches),
    false,
    'an unrecorded line in a matched file must still be rejected',
  );
  console.log('PASS T18 downstream admission binds the exact AST-matched line');
} finally {
  await rm(dir, { recursive: true, force: true });
  await rm(outsideDir, { recursive: true, force: true });
}
