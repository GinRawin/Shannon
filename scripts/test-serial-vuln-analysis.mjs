import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createAnalysisScheduler } from '../apps/worker/dist/temporal/analysis-scheduler.js';

const flush = () => new Promise(setImmediate);
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

test('serial analysis admits one activity at a time, releasing before exploitation ends', async () => {
  const schedule = createAnalysisScheduler(true);
  const analyses = [deferred(), deferred()];
  const exploits = [deferred(), deferred()];
  const events = [];
  const lane = async index => {
    await schedule(async () => { events.push(`analysis-${index}`); await analyses[index].promise; });
    events.push(`exploit-${index}`);
    await exploits[index].promise;
  };
  const first = lane(0), second = lane(1);
  await flush(); assert.deepEqual(events, ['analysis-0']);
  analyses[0].resolve(); await flush();
  assert.ok(events.includes('analysis-1'));
  assert.ok(events.includes('exploit-0'));
  analyses[1].resolve(); await flush();
  assert.ok(events.includes('exploit-1')); // First exploitation is still running.
  exploits.forEach(item => item.resolve()); await Promise.all([first, second]);
});

test('default scheduling starts analyses in parallel', async () => {
  const schedule = createAnalysisScheduler(false);
  const first = deferred(), second = deferred();
  const events = [];
  const a = schedule(async () => { events.push('first'); await first.promise; });
  const b = schedule(async () => { events.push('second'); await second.promise; });
  assert.deepEqual(events, ['first', 'second']);
  first.resolve(); second.resolve(); await Promise.all([a, b]);
});

test('failed analysis does not block the next category', async () => {
  const schedule = createAnalysisScheduler(true);
  const failure = schedule(async () => { throw new Error('analysis failed'); });
  const checked = assert.rejects(failure, /analysis failed/);
  const next = schedule(async () => 'next category');
  await checked; assert.equal(await next, 'next category');
});

test('CLI forwards the opt-in flag to the worker and omits it by default', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const cli = path.join(root, 'apps/cli/dist/index.mjs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shannon-serial-cli-'));
  try {
    const bin = path.join(dir, 'bin'), repo = path.join(dir, 'repo'), trace = path.join(dir, 'docker.jsonl');
    fs.mkdirSync(bin); fs.mkdirSync(repo);
    const fakeDocker = `#!${process.execPath}\nimport fs from 'node:fs'; const args=process.argv.slice(2); fs.appendFileSync(${JSON.stringify(trace)},JSON.stringify(args)+'\\n'); if(args[0]==='run')process.exit(1); if(args.includes('health'))console.log('SERVING'); if(args[0]==='image'&&args.includes('--format'))console.log('workflow-id-v1'); if(args.includes('describe'))console.log('WorkflowExecutionRetentionTtl 168h');`;
    fs.writeFileSync(path.join(bin, 'docker'), fakeDocker, { mode: 0o755 });
    const env = { PATH: `${bin}${path.delimiter}${process.env.PATH}`, SHANNON_LOCAL: '1', SHANNON_AI_MODEL: 'fixture:fixture', SHANNON_AI_API_KEY: 'test' };
    const help = spawnSync(process.execPath, [cli, 'start', '--help'], { cwd: dir, env, encoding: 'utf8' });
    assert.ifError(help.error);
    assert.equal(help.status, 0, help.stderr || String(help.error));
    assert.match(help.stdout, /--serial-vuln-analysis/);
    for (const serial of [true, false]) {
      fs.writeFileSync(trace, '');
      const args = [cli, 'start', '-u', 'https://fixture.invalid', '-r', repo, ...(serial ? ['--serial-vuln-analysis'] : [])];
      const result = spawnSync(process.execPath, args, { cwd: dir, env, encoding: 'utf8', timeout: 15000 });
      assert.ifError(result.error);
      assert.equal(result.status, 1); // Fake Docker rejects launch; no real scan is created.
      const calls = fs.readFileSync(trace, 'utf8').trim().split('\n').map(line => JSON.parse(line));
      const launch = calls.find(call => call[0] === 'run');
      assert.ok(launch, result.stderr);
      assert.equal(launch.includes('--serial-vuln-analysis'), serial);
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
