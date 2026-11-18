/**
 * End-to-end acceptance for the real Explore activity (`runExploreAgent`) on the AST v3 path.
 *
 * Unlike scripts/test-explore-ast-clone-search.mjs (which calls the retrieval service directly),
 * this drives the *exported Temporal activity* against a temporary git workspace: it builds the
 * Record-verified seed set, runs the activity, and inspects the artifacts the activity actually
 * committed with `writeAndCommitExactFiles`.
 *
 * Run `pnpm --filter @shannon/worker build` first, then:
 *   node scripts/test-explore-ast-activity.mjs
 *
 * checks: default (no env) -> AST v3; explicit SHANNON_EXPLORE_ALGORITHM=token -> v2;
 * explicit v3 -> v3; seed gating (only record-verified+exploited); committed artifact shape;
 * null-declared template artifacts stay absent; re-run is idempotent (no duplicate commit).
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = path.join(REPO, 'scripts/fixtures/explore-ast/repo/src');
const { runExploreAgent } = await import(path.join(REPO, 'apps/worker/dist/temporal/activities.js'));

// Provide a Temporal Activity context so activity-logger's Context.current() works offline.
import { createRequire } from 'node:module';
const requireFromWorker = createRequire(path.join(REPO, 'apps/worker/dist/temporal/worker.js'));
const activityMod = await import(requireFromWorker.resolve('@temporalio/activity'));
const activityContext = new activityMod.Context(
  {
    taskToken: new Uint8Array(), base64TaskToken: '', activityId: 'explore-real', activityType: 'runExploreAgent',
    activityNamespace: 'default', attempt: 1, isLocal: true, headers: {}, priority: { priorityKey: 0 },
    workflowExecution: { workflowId: 'explore-real', runId: 'run-1' },
    workflowType: 'pentest', workflowNamespace: 'default', taskQueue: 'default',
    heartbeatDetails: undefined, workflowTaskTimeout: 10_000,
  },
  new Promise(() => {}),
  () => {},
);
activityContext.log = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {}, trace: () => {} };
const runInActivityContext = (fn) => activityMod.asyncLocalStorage.run(activityContext, fn);

async function makeWorkspace(label) {
  const root = await mkdtemp(path.join(tmpdir(), `explore-real-${label}-`));
  await cp(FIXTURES, path.join(root, 'src'), { recursive: true });
  const deliv = path.join(root, '.shannon', 'deliverables');
  await mkdir(deliv, { recursive: true });
  const seedLine = (await readFile(path.join(root, 'src/orders.ts'), 'utf8'))
    .split('\n').findIndex((l) => l.includes('SELECT id, total FROM orders')) + 1;
  await writeFile(path.join(deliv, 'record_verified_finding_ids.json'), JSON.stringify(['INJ-01']));
  await writeFile(path.join(deliv, 'injection_exploit_collector_renumbered.json'), JSON.stringify([
    { vulnerability_id: 'INJ-01', status: 'exploited',
      code_locations: [{ workspace_relative_file_path: 'src/orders.ts', line_number: seedLine }] },
    // record-unverified + non-exploited must never become seeds
    { vulnerability_id: 'INJ-99', status: 'exploited',
      code_locations: [{ workspace_relative_file_path: 'src/tickets.ts', line_number: 1 }] },
    { vulnerability_id: 'INJ-01', status: 'pending',
      code_locations: [{ workspace_relative_file_path: 'src/admin.ts', line_number: 1 }] },
  ]));
  // Production initializes the *deliverables* directory as its own git repo (activities.ts:3163).
  execFileSync('git', ['init', '-q'], { cwd: deliv });
  execFileSync('git', ['add', '-A'], { cwd: deliv });
  execFileSync('git', ['commit', '-qm', 'deliverables seed inputs'], { cwd: deliv });
  return { root, deliv, seedLine };
}

function readArtifacts(deliv) {
  return readFile(path.join(deliv, 'explore_search_results.json'), 'utf8').then(JSON.parse);
}

async function run(label, env) {
  const { root, deliv, seedLine } = await makeWorkspace(label);
  const saved = process.env.SHANNON_EXPLORE_ALGORITHM;
  if (env === undefined) delete process.env.SHANNON_EXPLORE_ALGORITHM; else process.env.SHANNON_EXPLORE_ALGORITHM = env;
  let metrics;
  try {
    metrics = await runInActivityContext(() => runExploreAgent({
      webUrl: 'https://fixture.example.test',
      repoPath: root,
      workflowId: `explore-real-${label}`,
      sessionId: `explore-real-${label}`,
      outputPath: root,
      deliverablesSubdir: '.shannon/deliverables',
    }));
  } finally {
    if (saved === undefined) delete process.env.SHANNON_EXPLORE_ALGORITHM; else process.env.SHANNON_EXPLORE_ALGORITHM = saved;
  }
  const result = await readArtifacts(deliv);
  const coverage = JSON.parse(await readFile(path.join(deliv, 'explore_clone_coverage.json'), 'utf8'));
  const seeds = JSON.parse(await readFile(path.join(deliv, 'explore_seeds.json'), 'utf8'));
  const md = await readFile(path.join(deliv, 'explore_deliverable.md'), 'utf8');
  // Git: artifacts really committed by the activity
  const status = execFileSync('git', ['status', '--porcelain'], { cwd: deliv }).toString();
  const log = execFileSync('git', ['log', '--oneline', '--name-only', '-1'], { cwd: deliv }).toString();
  return { root, deliv, seedLine, metrics, result, coverage, seeds, md, status, log };
}

const ast = await run('v3-default', undefined);
console.log('--- default (no env) ---');
console.log('metrics', JSON.stringify(ast.metrics));
console.log('git status (should be clean):', JSON.stringify(ast.status));
console.log('HEAD commit files:\n' + ast.log);

assert.equal(ast.result.schema_version, 3, 'default must be AST v3');
assert.equal(ast.result.algorithm, 'ast_structural_clone_v1');
assert.equal(ast.result.statistics.seed_count, 1, 'only the record-verified, exploited seed is collected');
assert.equal(ast.seeds.seeds.length, 1);
assert.ok(ast.result.matches.length > 0, 'the real activity must return matches');
assert.equal(ast.result.matches[0].seed_file, 'src/orders.ts');
console.log('default => schema', ast.result.schema_version, ast.result.algorithm, 'matches', ast.result.matches.length);
console.log('deliverable.md head:', JSON.stringify(ast.md.split('\n').slice(0, 6)));
console.log('PASS real activity: default env -> AST v3 artifacts committed\n');

const v2 = await run('v2-explicit', 'token');
console.log('--- explicit token (v2) ---');
assert.equal(v2.result.schema_version, 2, 'explicit token must select v2');
assert.equal(v2.result.algorithm, 'normalized_token_clone_v1');
console.log('explicit token => schema', v2.result.schema_version, v2.result.algorithm, 'matches', v2.result.matches.length);
console.log('PASS real activity: explicit SHANNON_EXPLORE_ALGORITHM=token -> v2 artifacts committed\n');

const v3named = await run('v3-named', 'v3');
assert.equal(v3named.result.schema_version, 3, 'explicit v3 must select v3');
console.log('explicit v3 => schema', v3named.result.schema_version, v3named.result.algorithm);
console.log('PASS real activity: explicit v3 -> AST v3\n');

// --- resume / lost-ack idempotency on the real activity -------------------------------
const resumeRoot = await (async () => {
  const w = await makeWorkspace('resume');
  return w;
})();
const callActivity = (input) => runInActivityContext(() => runExploreAgent(input));
const input = {
  webUrl: 'https://fixture.example.test',
  repoPath: resumeRoot.root,
  workflowId: 'explore-real-resume',
  sessionId: 'explore-real-resume',
  outputPath: resumeRoot.root,
  deliverablesSubdir: '.shannon/deliverables',
};
const first = await callActivity(input);
const firstHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: resumeRoot.deliv }).toString().trim();
const second = await callActivity(input);
const secondHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: resumeRoot.deliv }).toString().trim();
const commitCount = execFileSync('git', ['rev-list', '--count', 'HEAD'], { cwd: resumeRoot.deliv }).toString().trim();
assert.equal(firstHead, secondHead, 're-running the activity must not create a second commit');
assert.equal(commitCount, '2', 'deliverables repo keeps exactly the input commit + one output commit');
assert.equal(execFileSync('git', ['status', '--porcelain'], { cwd: resumeRoot.deliv }).toString(), '');
const committed = JSON.parse(await readFile(path.join(resumeRoot.deliv, 'explore_search_results.json'), 'utf8'));
assert.equal(committed.schema_version, 3);
assert.equal(committed.matches[0].algorithm ?? 'ast_structural_clone_v1', 'ast_structural_clone_v1');
assert.equal(committed.matches[0].seed_file, 'src/orders.ts');
assert.equal(committed.matches.every((m) => m.ast_evidence.anchor_mapped === true), true);
const cov = JSON.parse(await readFile(path.join(resumeRoot.deliv, 'explore_clone_coverage.json'), 'utf8'));
for (const key of ['parse_failed_files','indexed_forests','retrieval_candidates','reranked_candidates','unmapped_anchors','ambiguous_anchors','matcher_budget_exceeded','parser_language_unsupported']) {
  assert.ok(typeof cov.summary[key] === 'number', `coverage summary must expose ${key}`);
}
let templatesAbsent = false;
try { await readFile(path.join(resumeRoot.deliv, 'explore_templates.json'), 'utf8'); } catch (e) { templatesAbsent = e.code === 'ENOENT'; }
assert.equal(templatesAbsent, true, 'null-declared template artifact must stay absent');
console.log('PASS real activity: re-run is idempotent (no duplicate commit), artifacts well-formed, template artifacts absent');
await rm(resumeRoot.root, { recursive: true, force: true });

for (const w of [ast, v2, v3named]) await rm(w.root, { recursive: true, force: true });
console.log('ALL REAL-ACTIVITY ACCEPTANCE CHECKS PASSED');
