/**
 * Offline fixture test for the deterministic Type-2/Type-3 Explore clone retrieval.
 *
 * Run `pnpm --filter @shannon/worker build` first, then:
 *   node scripts/test-explore-clone-search.mjs
 *
 * The fixture repository lives under scripts/fixtures/explore-clone/repo and is copied into a
 * temporary directory so symlink and path-escape cases can be created safely.
 */
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { searchCloneCandidates } from '../apps/worker/dist/services/explore-clone-search.js';
import { locationMatchesExploreSearch } from '../apps/worker/dist/services/explore-search.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = path.join(repoRoot, 'scripts', 'fixtures', 'explore-clone', 'repo');
const dir = await mkdtemp(path.join(tmpdir(), 'shannon-clone-test-'));
const outsideDir = `${dir}-outside`;

async function lineOf(relative, needle) {
  const text = await readFile(path.join(dir, relative), 'utf8');
  const index = text.split('\n').findIndex((line) => line.includes(needle));
  assert.ok(index >= 0, `fixture ${relative} must contain ${needle}`);
  return index + 1;
}

try {
  await cp(fixtures, dir, { recursive: true });
  await mkdir(outsideDir, { recursive: true });
  await writeFile(path.join(outsideDir, 'escape.ts'), 'export const leaked = 1;\n');
  await symlink(path.join(outsideDir, 'escape.ts'), path.join(dir, 'src', 'escape.ts'));

  const seedLine = await lineOf('src/orders.ts', 'SELECT id, total FROM orders');
  const documentLine = await lineOf('src/documents.ts', 'SELECT id, title FROM documents');
  const invoiceLine = await lineOf('src/invoices.ts', 'SELECT id, amount FROM invoices');
  const userLine = await lineOf('src/users.ts', 'SELECT id, email FROM users');
  const reportLine = await lineOf('src/reports.ts', 'SELECT id, body FROM reports');
  const ticketLine = await lineOf('src/tickets.ts', 'SELECT id, subject FROM tickets');
  const paymentLine = await lineOf('src/payments.ts', 'SELECT id, amount FROM payments');
  const adminLine = await lineOf('src/admin.ts', 'SELECT id, total FROM orders');
  const headerLine = await lineOf('src/documents.ts', 'export async function getDocumentById');

  const seeds = [
    { findingId: 'INJ-01', vulnerabilityClass: 'injection', file: 'src/orders.ts', line: seedLine },
    { findingId: 'INJ-02', vulnerabilityClass: 'injection', file: 'src/missing.ts', line: 3 },
    { findingId: 'INJ-03', vulnerabilityClass: 'injection', file: 'src/legacy.py', line: 3 },
    { findingId: 'INJ-04', vulnerabilityClass: 'injection', file: 'src/tiny.ts', line: 1 },
    { findingId: 'INJ-05', vulnerabilityClass: 'injection', file: 'src/escape.ts', line: 1 },
  ];

  const outcome = await searchCloneCandidates(dir, seeds);
  const matches = outcome.result.matches;
  const find = (file) => matches.find((match) => match.match_file === file);

  assert.equal(outcome.result.schema_version, 2);
  assert.equal(outcome.result.algorithm, 'normalized_token_clone_v1');
  assert.equal(outcome.result.truncated, false, 'a small fixture repository must not truncate');
  assert.equal(outcome.seeds.seeds.length, seeds.length);

  const cloned = find('src/documents.ts');
  assert.ok(cloned, 'the Type-2 rename/literal clone must be retrieved');
  assert.equal(cloned.match_line, documentLine, 'match_line must be the real statement line of the clone');
  assert.notEqual(cloned.match_line, headerLine, 'match_line must not fall back to the candidate function head');
  assert.ok(cloned.score >= 0.9, `Type-2 clone score ${cloned.score} should be near 1.0`);
  assert.equal(cloned.finding_id, 'INJ-01');
  assert.equal(cloned.vulnerability_class, 'injection');
  assert.equal(cloned.seed_file, 'src/orders.ts');
  assert.equal(cloned.seed_line, seedLine);
  assert.equal(cloned.candidate_start_line <= cloned.match_line && cloned.match_line <= cloned.candidate_end_line, true);

  // Every labelled Type-2 / Type-3 variant must land in the seed's Top-10 (Recall@10 = 100%).
  const labelled = [
    ['src/documents.ts', documentLine, 'Type-2 rename + string literal'],
    ['src/invoices.ts', invoiceLine, 'Type-2 rename + string literal'],
    ['src/users.ts', userLine, 'Type-2 rename + string literal'],
    ['src/reports.ts', reportLine, 'Type-3 insertion + deletion'],
    ['src/tickets.ts', ticketLine, 'Type-3 insertion'],
    ['src/payments.ts', paymentLine, 'Type-3 deletion'],
  ];
  for (const [file, line, kind] of labelled) {
    const hit = find(file);
    assert.ok(hit, `the ${kind} clone ${file} must be retrieved`);
    assert.equal(hit.match_line, line, `${file} match_line must be the real statement line of the clone`);
    assert.ok(hit.score >= 0.55, `${file} score ${hit.score} must clear the similarity threshold`);
  }
  assert.ok(matches.length >= labelled.length, 'all labelled variants must be recalled in one pass');

  const edited = find('src/reports.ts');
  assert.ok(edited, 'the Type-3 insertion/deletion clone must be retrieved');
  assert.equal(edited.match_line, reportLine, 'Type-3 match_line must be the shifted real statement');
  assert.ok(edited.score > 0.55 && edited.score < cloned.score, `Type-3 score ${edited.score} must sit below the Type-2 score`);
  assert.ok(find('src/payments.ts').score < cloned.score, 'the deletion-only variant must score below a near-identical Type-2');

  const safe = find('src/admin.ts');
  assert.ok(safe, 'a safe clone with an extra authorization check is still a retrieval candidate');
  assert.equal(safe.match_line, adminLine);

  assert.equal(find('src/orders.ts'), undefined, 'the seed location must not be returned as a new match');
  assert.equal(find('src/cache.ts'), undefined, 'an unrelated implementation sharing only the method name must not match');
  assert.equal(find('src/metrics.ts'), undefined, 'an unrelated implementation must not match');

  const reasons = new Map(outcome.result.skipped_seeds.map((record) => [record.finding_id, record.reason]));
  assert.equal(reasons.get('INJ-02'), 'seed_file_missing');
  assert.equal(reasons.get('INJ-03'), 'unsupported_language');
  assert.equal(reasons.get('INJ-04'), 'seed_too_short');
  assert.equal(reasons.get('INJ-05'), 'seed_path_outside_repository');
  assert.equal(outcome.result.statistics.eligible_seed_count, 1);
  assert.equal(outcome.coverage.summary.indexed_files >= 8, true);
  assert.equal(outcome.coverage.summary.matched, matches.length);

  const order = matches.map((match) => `${match.match_file}:${match.match_line}`);
  const sorted = [...order].sort((left, right) => order.indexOf(left) - order.indexOf(right));
  assert.deepEqual(order, sorted, 'matches are returned in a stable score/file/line order');
  assert.ok(matches.indexOf(cloned) < matches.indexOf(edited), 'the stronger clone must rank above the weaker one');

  const repeat = await searchCloneCandidates(dir, seeds);
  assert.equal(
    JSON.stringify(repeat.result),
    JSON.stringify(outcome.result),
    'identical input must produce byte-identical results',
  );
  console.log('PASS Type-2/Type-3 clone retrieval, skip reasons, dedupe, ordering, and determinism');

  const bounded = await searchCloneCandidates(dir, seeds, { maxTotalMatches: 1 });
  assert.equal(bounded.result.matches.length, 1);
  assert.equal(bounded.result.truncated, true, 'hitting the global match cap must disclose truncation');
  console.log('PASS the global match cap is enforced and disclosed');

  // --- Java fixture block -----------------------------------------------------
  // A Java seed must retrieve Java Type-2/Type-3 clones only, without reading the JS/TS side.
  const javaSeedLine = await lineOf('src/OrderDao.java', 'statement.executeQuery(sql)');
  const javaDocumentLine = await lineOf('src/DocumentDao.java', 'stmt.executeQuery(query)');
  const javaInvoiceLine = await lineOf('src/InvoiceDao.java', 'stmt.executeQuery(query)');
  const javaUserLine = await lineOf('src/UserDao.java', 'statement.executeQuery(sql)');
  const javaTicketLine = await lineOf('src/TicketDao.java', 'stmt.executeQuery(query)');
  const javaReportLine = await lineOf('src/ReportDao.java', 'stmt.executeQuery(query)');
  const javaPaymentLine = await lineOf('src/PaymentDao.java', 'stmt.executeQuery(query)');
  const javaAdminLine = await lineOf('src/AdminOrderDao.java', 'statement.executeQuery(sql)');

  const javaSeeds = [
    { findingId: 'JINJ-01', vulnerabilityClass: 'injection', file: 'src/OrderDao.java', line: javaSeedLine },
    { findingId: 'JINJ-02', vulnerabilityClass: 'injection', file: 'src/legacy.py', line: 3 },
  ];
  const javaOutcome = await searchCloneCandidates(dir, javaSeeds);
  const javaMatches = javaOutcome.result.matches;
  const javaFind = (file) => javaMatches.find((match) => match.match_file === file);

  assert.equal(javaOutcome.result.statistics.eligible_seed_count, 1);
  const javaSourceCount = (await readdir(path.join(dir, 'src'))).filter((name) => name.endsWith('.java')).length;
  assert.equal(
    javaOutcome.coverage.summary.indexed_files,
    javaSourceCount,
    'a Java-only seed must index exactly the Java sources and skip the JavaScript/TypeScript side',
  );
  assert.equal(
    javaOutcome.result.skipped_seeds.find((record) => record.finding_id === 'JINJ-02').reason,
    'unsupported_language',
    'a non-Java/TypeScript seed is still reported as unsupported_language',
  );

  const javaCloned = javaFind('src/DocumentDao.java');
  assert.ok(javaCloned, 'the Java Type-2 clone must be retrieved');
  assert.equal(javaCloned.match_line, javaDocumentLine, 'the Java clone match_line must be the real statement line');
  assert.ok(javaCloned.score >= 0.9, `Java Type-2 clone score ${javaCloned.score} should be near 1.0`);
  assert.equal(javaCloned.seed_file, 'src/OrderDao.java');
  assert.equal(javaCloned.seed_line, javaSeedLine);
  assert.equal(javaCloned.finding_id, 'JINJ-01');
  assert.equal(javaCloned.vulnerability_class, 'injection');

  const javaLabelled = [
    ['src/InvoiceDao.java', javaInvoiceLine, 'Type-2 rename + string literal'],
    ['src/UserDao.java', javaUserLine, 'Type-2 rename'],
    ['src/TicketDao.java', javaTicketLine, 'Type-3 insertion'],
    ['src/ReportDao.java', javaReportLine, 'Type-3 insertion + deletion'],
    ['src/PaymentDao.java', javaPaymentLine, 'Type-3 deletion'],
  ];
  for (const [file, line, kind] of javaLabelled) {
    const hit = javaFind(file);
    assert.ok(hit, `the Java ${kind} clone ${file} must be retrieved`);
    assert.equal(hit.match_line, line, `${file} match_line must be the real statement line of the clone`);
    assert.ok(hit.score >= 0.55, `${file} score ${hit.score} must clear the similarity threshold`);
  }
  assert.ok(javaFind('src/PaymentDao.java').score < javaCloned.score, 'the Java deletion variant must score below a near-identical Type-2');

  const javaSafe = javaFind('src/AdminOrderDao.java');
  assert.ok(javaSafe, 'a safe Java clone with an extra authorization check is still a retrieval candidate');
  assert.equal(javaSafe.match_line, javaAdminLine);

  assert.equal(javaFind('src/OrderDao.java'), undefined, 'the Java seed location must not be returned as a new match');
  assert.equal(javaFind('src/CacheOrderDao.java'), undefined, 'a Java file sharing only the method name must not match');
  assert.equal(javaFind('src/documents.ts'), undefined, 'a Java-only seed must never return a JavaScript/TypeScript clone');
  assert.equal(javaOutcome.coverage.summary.matched, javaMatches.length);

  const javaOrder = javaMatches.map((match) => `${match.match_file}:${match.match_line}`);
  assert.deepEqual(
    javaOrder,
    [...javaOrder].sort((left, right) => javaOrder.indexOf(left) - javaOrder.indexOf(right)),
    'Java matches are returned in a stable score/file/line order',
  );

  const javaRepeat = await searchCloneCandidates(dir, javaSeeds);
  assert.equal(
    JSON.stringify(javaRepeat.result),
    JSON.stringify(javaOutcome.result),
    'identical Java input must produce byte-identical results',
  );
  console.log('PASS Java Type-2/Type-3 clone retrieval, language isolation, safe variant, and determinism');

  assert.equal(
    locationMatchesExploreSearch({ file: cloned.match_file, start_line: cloned.match_line, role: 'sink' }, matches),
    true,
    'a sink location covering the clone match line must be admitted downstream',
  );
  assert.equal(
    locationMatchesExploreSearch({ file: cloned.match_file, start_line: headerLine, role: 'sink' }, matches),
    false,
    'a location that only names the candidate file must still be rejected',
  );
  assert.equal(
    locationMatchesExploreSearch({ file: edited.match_file, start_line: reportLine + 40, role: 'sink' }, matches),
    false,
    'an unrecorded line in a matched file must still be rejected',
  );
  console.log('PASS downstream admission binds the exact clone line');
} finally {
  await rm(dir, { recursive: true, force: true });
  await rm(outsideDir, { recursive: true, force: true });
}
