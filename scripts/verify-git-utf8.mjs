// Run after building the worker: node scripts/verify-git-utf8.mjs
// All writes and Git mutations stay in temporary fixture repositories.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (name) => import(pathToFileURL(path.join(root, 'apps/worker/dist', `${name}.js`)));
const { readCommittedFile, readFileFromHead, classifyHeadReadFailure } = await load('services/git-manager');
const { writeAndCommitExactFiles } = await load('services/exact-output-commit');
const { compactReportFindings } = await load('services/compaction-core');
const { finalizeReport } = await load('services/report-finalization');
const temporary = await mkdtemp(path.join(tmpdir(), 'shannon-git-utf8-'));
const logger = { info() {}, warn() {}, error() {} };
const digest = (value) => createHash('sha256').update(value).digest('hex');

async function git(args) {
  const chunks = [];
  const errors = [];
  await new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd: temporary, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', (chunk) => chunks.push(chunk));
    child.stderr.on('data', (chunk) => errors.push(chunk));
    child.once('error', reject);
    child.once('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`Fixture Git command failed: ${Buffer.concat(errors).toString('utf8')}`));
    });
  });
  return Buffer.concat(chunks);
}

async function check(name, body) {
  await body();
  console.log(`PASS ${name}`);
}

try {
  await git(['init', '-q']);
  await git(['config', 'user.name', 'UTF-8 regression']);
  await git(['config', 'user.email', 'utf8@example.invalid']);

  await check('split UTF-8 code points, BOM and missing final newline survive both HEAD readers', async () => {
    const bin = path.join(temporary, 'bin');
    await mkdir(bin);
    const executable = path.join(bin, 'git');
    // Emit one byte per event to force boundaries inside three- and four-byte characters.
    const contents = '\uFEFF中文🙂';
    await writeFile(executable, `#!${process.execPath}
if (process.env.LC_ALL !== 'C') process.exit(2);
const bytes = Buffer.from(${JSON.stringify(contents)});
let offset = 0;
function emit() {
  if (offset === bytes.length) return;
  process.stdout.write(bytes.subarray(offset, ++offset));
  setTimeout(emit, 10);
}
emit();
`);
    await chmod(executable, 0o755);
    const previousPath = process.env.PATH;
    process.env.PATH = `${bin}${path.delimiter}${previousPath ?? ''}`;
    try {
      assert.deepEqual(await readCommittedFile(temporary, 'split.txt'), { state: 'present', contents });
      assert.equal(await readFileFromHead(temporary, 'split.txt'), contents);
    } finally {
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
    }
  });

  const overview = '中文漏洞报告：请求与响应，认证与授权。🙂 café 日本語\r\n'.repeat(40000);
  const report = {
    report_meta: {
      target: 'https://example.invalid/', assessment_date: '2026-10-15',
      scope: '授权检查', executive_summary: '中文报告回归验证',
    },
    findings: [{
      finding_id: 'AUTHZ-02', title: '中文授权漏洞', category: 'Authorization', severity: 'high',
      owasp_category: 'A01:2025 — Broken Access Control', status: 'exploited',
      vulnerable_location: 'GET /fixture', auth_state: '低权限用户', prerequisites: '测试会话',
      overview, impact: '读取测试记录', remediation: '检查对象权限',
      exploitation_steps: [{ title: '测试请求', items: [{ kind: 'prose', text: '读取测试对象' }] }],
    }],
    reconciliation_failed: [],
  };
  const originalJson = `${JSON.stringify(report, null, 2)}\n`;
  await writeFile(path.join(temporary, 'report.json'), originalJson);
  await writeFile(path.join(temporary, 'empty.txt'), '');
  await writeFile(path.join(temporary, 'ascii.txt'), 'ASCII without final newline');
  await writeFile(path.join(temporary, 'bom.txt'), '\uFEFF中文\r\n');
  await writeFile(path.join(temporary, 'authz_renumber_map.json'), JSON.stringify({
    vulnerability_type: 'authz', map: { 'AUTHZ-04': 'AUTHZ-01', 'AUTHZ-09': 'AUTHZ-02' },
    order: ['AUTHZ-04', 'AUTHZ-09'], excluded: [],
  }));
  await writeFile(path.join(temporary, 'authz_exploit_collector_renumbered.json'), JSON.stringify([
    { vulnerability_id: 'AUTHZ-01', status: 'exploited' },
    { vulnerability_id: 'AUTHZ-02', status: 'exploited', overview },
  ]));
  await git(['add', 'report.json', 'empty.txt', 'ascii.txt', 'bom.txt',
    'authz_renumber_map.json', 'authz_exploit_collector_renumbered.json']);
  await git(['commit', '-qm', 'Synthetic Chinese report']);

  await check('large multilingual report is byte-identical across repeated reads', async () => {
    assert.ok(Buffer.byteLength(originalJson) > 2 * 1024 * 1024);
    for (let index = 0; index < 5; index++) {
      const result = await readCommittedFile(temporary, 'report.json');
      assert.equal(result.state, 'present');
      assert.equal(digest(result.contents), digest(originalJson));
      assert.equal(digest(await readFileFromHead(temporary, 'report.json')), digest(originalJson));
    }
    for (const filename of ['empty.txt', 'ascii.txt', 'bom.txt']) {
      assert.deepEqual(await readCommittedFile(temporary, filename), {
        state: 'present', contents: await readFile(path.join(temporary, filename), 'utf8'),
      });
    }
  });

  await check('absent, corrupt and transient errors keep their existing classification', async () => {
    assert.deepEqual(await readCommittedFile(temporary, 'absent.txt'), { state: 'absent' });
    assert.equal(await readFileFromHead(temporary, 'absent.txt'), null);
    assert.equal(classifyHeadReadFailure('fatal: bad object HEAD'), 'corrupt');
    assert.equal(classifyHeadReadFailure('Permission denied; bad object HEAD'), 'transient');
    assert.equal(classifyHeadReadFailure('unexpected repository failure'), 'transient');
    const missingRepository = path.join(temporary, 'missing-repository');
    await assert.rejects(readCommittedFile(missingRepository, 'report.json'), {
      name: 'PentestError', code: 'GIT_CHECKPOINT_FAILED', retryable: true,
    });
    assert.equal(await readFileFromHead(missingRepository, 'report.json'), null);
    const sha = (await git(['rev-parse', 'HEAD:ascii.txt'])).toString('utf8').trim();
    const objectPath = path.join(temporary, '.git/objects', sha.slice(0, 2), sha.slice(2));
    const originalObject = await readFile(objectPath);
    try {
      await chmod(objectPath, 0o644);
      await writeFile(objectPath, '');
      assert.deepEqual(await readCommittedFile(temporary, 'ascii.txt'), { state: 'corrupt' });
    } finally {
      await writeFile(objectPath, originalObject);
    }
  });

  await check('exact publication verifies large Chinese bytes and safely adopts a repeat', async () => {
    const files = [{ relPath: 'published.txt', contents: overview }];
    const first = await writeAndCommitExactFiles(temporary, files, 'Publish multilingual fixture', logger);
    assert.equal(first.alreadyCommitted, false);
    assert.equal(digest(await git(['show', 'HEAD:published.txt'])), digest(overview));
    const second = await writeAndCommitExactFiles(temporary, files, 'Repeat publication', logger);
    assert.equal(second.alreadyCommitted, true);
    assert.equal(second.commitHash, first.commitHash);
  });

  await check('report compaction and finalization preserve Chinese text and remain repeatable', async () => {
    const compacted = await compactReportFindings({
      deliverablesDir: temporary, participatingClasses: ['authz'], renumberFailedClasses: [], logger,
    });
    assert.equal(compacted.skipped, false);
    const draft = JSON.parse(await readFile(path.join(temporary, 'report.json'), 'utf8'));
    assert.equal(draft.findings[0].finding_id, 'AUTHZ-01');
    assert.equal(digest(draft.findings[0].overview), digest(overview));
    const options = {
      deliverablesDir: temporary, exploit: true, partialReasons: [], reconciliationFailedClasses: [],
      reportConfig: { sarif: true }, workspaceName: 'utf8-regression', logger,
      // PDF rendering is outside this regression; exercise its warning path without external tools.
      renderPdf: async () => { throw new Error('PDF renderer intentionally unavailable in fixture'); },
    };
    const finalized = await finalizeReport(options);
    assert.equal(finalized.commit.alreadyCommitted, false);
    for (const artifact of ['report_json', 'markdown', 'sarif']) {
      const receipt = finalized.manifest.artifacts[artifact];
      const bytes = await git(['show', `HEAD:${receipt.path}`]);
      assert.equal(digest(bytes), receipt.sha256);
      assert.equal(bytes.toString('utf8').includes('\uFFFD'), false);
    }
    const finalReport = JSON.parse(await readFile(path.join(temporary, 'report.json'), 'utf8'));
    assert.equal(digest(finalReport.findings[0].overview), digest(overview));
    const repeated = await finalizeReport(options);
    assert.equal(repeated.commit.alreadyCommitted, true);
    assert.equal(repeated.commit.commitHash, finalized.commit.commitHash);
  });
} finally {
  await rm(temporary, { recursive: true, force: true });
}
