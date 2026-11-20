/**
 * Offline importer CLI for the Java security rule set.
 *
 * Run `pnpm --filter @shannon/worker build` first, then e.g.:
 *   node scripts/import-java-security-rules.mjs --format codeql --out /tmp/rules.json \
 *     --base apps/worker/src/services/java-security/data/java-security-rules.json \
 *     --report /tmp/rule-import-report.json /path/to/model.yml /path/to/another.model.yml
 *
 * It converts upstream models into the normalized schema and writes a versioned JSON rule set plus
 * a report. It performs no network access and is not used at scan time.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  buildRuleSetArtifact,
  mergeRuleSets,
  importRules,
} from '../apps/worker/dist/services/java-security/import/rules-importer.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const args = { inputs: [], format: 'codeql', out: undefined, report: undefined, base: undefined, version: undefined, generatedAt: undefined, repository: 'shannon:imported', commit: 'unknown', license: 'see-origin' };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const next = argv[i + 1];
    switch (token) {
      case '--format': args.format = next; i += 1; break;
      case '--out': args.out = next; i += 1; break;
      case '--report': args.report = next; i += 1; break;
      case '--base': args.base = next; i += 1; break;
      case '--version': args.version = next; i += 1; break;
      case '--generated-at': args.generatedAt = next; i += 1; break;
      case '--repository': args.repository = next; i += 1; break;
      case '--commit': args.commit = next; i += 1; break;
      case '--license': args.license = next; i += 1; break;
      default:
        if (token.startsWith('--')) throw new Error(`unknown flag ${token}`);
        args.inputs.push(token);
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));
if (args.inputs.length === 0 || args.out === undefined) {
  console.error('usage: node scripts/import-java-security-rules.mjs --format <codeql|taie|fsb> --out <file> [--report <file>] [--base <file>] <input...>');
  process.exit(2);
}

const inputs = await Promise.all(
  args.inputs.map(async (file) => ({
    path: path.relative(repoRoot, path.resolve(file)),
    format: args.format,
    content: await readFile(file, 'utf8'),
    repository: args.repository,
    commit: args.commit,
    license: args.license,
  })),
);

const result = importRules(inputs);
const baseRules = args.base ? JSON.parse(await readFile(args.base, 'utf8')).rules ?? [] : [];
const merged = baseRules.length > 0 ? mergeRuleSets(baseRules, result.rules) : result.rules;
const version = args.version ?? `imported-${new Date().toISOString().slice(0, 10)}`;
const artifact = buildRuleSetArtifact(merged, version, args.generatedAt ?? new Date().toISOString().slice(0, 10));

await writeFile(args.out, `${JSON.stringify(artifact, null, 2)}\n`, 'utf8');
if (args.report !== undefined) {
  await writeFile(args.report, `${JSON.stringify({ ...result.report, mergedTotal: merged.length }, null, 2)}\n`, 'utf8');
}
console.log(
  `imported ${result.report.parsedRules} rules from ${result.report.sourceFiles} file(s); ` +
    `${result.report.unsupported} unsupported; ${merged.length} merged`,
);
