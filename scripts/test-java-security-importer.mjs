/**
 * Offline test for the Java security rule importer.
 *
 * Run `pnpm --filter @shannon/worker build` first, then:
 *   node scripts/test-java-security-importer.mjs
 */
import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { importRules, mergeRuleSets } from '../apps/worker/dist/services/java-security/import/rules-importer.js';

let checks = 0;
const ok = (condition, message) => {
  assert.ok(condition, message);
  checks += 1;
};

const dir = await mkdtemp(path.join(tmpdir(), 'shannon-jsec-import-'));

const codeqlPath = path.join(dir, 'model.yml');
await writeFile(
  codeqlPath,
  [
    'extensions:',
    '  - addsTo:',
    '      pack: codeql/java-all',
    '      extensible: sourceModel',
    '    data:',
    '      - ["java.net", "URL", True, "openConnection", "(...)", "", "ReturnValue", "remote", "manual"]',
    '  - addsTo:',
    '      pack: codeql/java-all',
    '      extensible: sinkModel',
    '    data:',
    '      - ["java.sql", "Statement", True, "executeQuery", "(String)", "", "Argument[0]", "sql-injection", "manual"]',
    '      - ["org.example", "Foo", True, "bar", "(...)", "", "ReturnValue.Element[0]", "sql", "manual"]',
  ].join('\n'),
  'utf8',
);

const taiePath = path.join(dir, 'taie.txt');
await writeFile(
  taiePath,
  ['<java.lang.Runtime: java.lang.Process exec(java.lang.String)>', 'index: 0'].join('\n'),
  'utf8',
);

const result = importRules([
  { path: 'model.yml', format: 'codeql', content: await (await import('node:fs/promises')).readFile(codeqlPath, 'utf8'), repository: 'github/codeql', commit: 'test', license: 'MIT' },
  { path: 'taie.txt', format: 'taie', content: await (await import('node:fs/promises')).readFile(taiePath, 'utf8'), repository: 'pascal-lab/Tai-e', commit: 'test', license: 'Apache-2.0' },
]);

const sink = result.rules.find((rule) => rule.match.method === 'executeQuery');
ok(sink !== undefined, 'codeql sink row is imported');
ok(sink.sensitive.target === 'argument' && sink.sensitive.indexes?.[0] === 0, 'Argument[0] maps to argument 0');
ok(sink.match.arity === 1, 'signature arity is derived');

const source = result.rules.find((rule) => rule.match.method === 'openConnection');
ok(source !== undefined && source.role === 'source', 'ReturnValue source is a return source');
ok(source.sensitive.target === 'return', 'ReturnValue never maps to argument 0');

ok(result.report.unsupported === 1, 'a composite ReturnValue.Element path is reported unsupported');
ok(
  result.report.unsupportedExamples.some((example) => example.includes('ReturnValue.Element')),
  'the unsupported access path is exemplified',
);

const exec = result.rules.find((rule) => rule.match.method === 'exec');
ok(exec !== undefined && exec.sensitive.indexes?.[0] === 0, 'tai-e index 0 maps to argument 0');

ok(result.report.byRole.sink === 2 && result.report.byRole.source === 1, 'report counts roles');
ok(result.report.parsedRules === result.rules.length, 'report counts parsed rules');

const merged = mergeRuleSets(result.rules, [
  { ...result.rules[0], id: 'merged:test', constant_filter: 'never' },
]);
ok(merged !== undefined, 'merge is deterministic');

const again = importRules([
  { path: 'model.yml', format: 'codeql', content: await (await import('node:fs/promises')).readFile(codeqlPath, 'utf8'), repository: 'github/codeql', commit: 'test', license: 'MIT' },
]);
ok(
  JSON.stringify(again.rules.map((r) => r.id)) ===
    JSON.stringify(result.rules.filter((r) => r.origin[0]?.repository === 'github/codeql').map((r) => r.id)),
  'import is repeatable and deterministic',
);

console.log(`java-security rule importer: ${checks} assertions passed`);
