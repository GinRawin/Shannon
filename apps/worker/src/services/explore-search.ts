import { spawn } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import path from 'node:path';
import type { ExploreTemplate } from '../collectors/explore-collector.js';

export interface ExploreSearchMatch {
  finding_id: string;
  vulnerability_class: string;
  sink_file: string;
  sink_line: number;
  regex: string;
  match_file: string;
  match_line: number;
  excerpt: string;
}

const SOURCE_GLOBS = [
  '*.c', '*.cc', '*.cpp', '*.h', '*.hpp', '*.go', '*.java', '*.kt', '*.js', '*.jsx', '*.mjs', '*.cjs',
  '*.ts', '*.tsx', '*.mts', '*.cts', '*.py', '*.rb', '*.php', '*.rs', '*.cs', '*.html', '*.vue', '*.svelte',
];
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_TOTAL_MATCHES = 500;
const MAX_MATCHES_PER_TEMPLATE = 40;

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function parseJsonMatches(output: string, root: string, template: ExploreTemplate): ExploreSearchMatch[] {
  const matches: ExploreSearchMatch[] = [];
  for (const line of output.split('\n')) {
    if (!line) continue;
    let event: Record<string, unknown>;
    try { event = JSON.parse(line) as Record<string, unknown>; } catch { continue; }
    if (event.type !== 'match' || !event.data || typeof event.data !== 'object') continue;
    const data = event.data as Record<string, unknown>;
    const pathData = data.path as { text?: unknown } | undefined;
    const linesData = data.lines as { text?: unknown } | undefined;
    if (typeof pathData?.text !== 'string' || typeof data.line_number !== 'number') continue;
    const absolute = path.resolve(root, pathData.text);
    if (!isInside(root, absolute)) continue;
    const excerpt = typeof linesData?.text === 'string' ? linesData.text.trim().slice(0, 800) : '';
    matches.push({
      finding_id: template.finding_id,
      vulnerability_class: template.vulnerability_class,
      sink_file: template.sink_file,
      sink_line: template.sink_line,
      regex: template.regex,
      match_file: path.relative(root, absolute).split(path.sep).join('/'),
      match_line: data.line_number,
      excerpt,
    });
  }
  return matches;
}

async function runRipgrep(root: string, pattern: string, onlyFile?: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    const args = [
      '--json', '--line-number', '--max-count', '8', '--max-columns', '1000', '--max-columns-preview', '--color', 'never',
      ...SOURCE_GLOBS.flatMap((glob) => ['--glob', glob]),
      '--glob', '!**/node_modules/**', '--glob', '!**/.git/**', '--glob', '!**/.shannon/**',
      '-e', pattern,
      ...(onlyFile ? ['--', onlyFile] : ['--', root]),
    ];
    const child = spawn('rg', args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > MAX_OUTPUT_BYTES) {
        child.kill('SIGTERM');
        reject(new Error('Search output limit exceeded.'));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (Buffer.concat(stderr).length < 16_000) stderr.push(chunk);
    });
    child.once('error', reject);
    child.once('close', (code) => {
      if (code === 0 || code === 1) resolve(Buffer.concat(stdout).toString('utf8'));
      else reject(new Error(`Source search failed (rg exit ${String(code)}): ${Buffer.concat(stderr).toString('utf8').slice(0, 1000)}`));
    });
  });
}

/** Search only source files with ripgrep's linear-time regex engine and verify each template against its claimed sink line. */
export async function searchExploreTemplates(
  sourceDir: string,
  templates: readonly ExploreTemplate[],
): Promise<{ matches: ExploreSearchMatch[]; rejected: Array<{ template: ExploreTemplate; reason: string }> }> {
  const root = await realpath(sourceDir);
  const matches: ExploreSearchMatch[] = [];
  const rejected: Array<{ template: ExploreTemplate; reason: string }> = [];
  for (const template of templates) {
    if (template.regex.length > 300 || template.regex.includes('\0')) {
      rejected.push({ template, reason: 'Template is too long or contains an invalid byte.' });
      continue;
    }
    const sinkAbsolute = path.resolve(root, template.sink_file);
    let sinkReal: string;
    try { sinkReal = await realpath(sinkAbsolute); } catch {
      rejected.push({ template, reason: 'Sink path does not exist in the assessed source tree.' });
      continue;
    }
    if (!isInside(root, sinkReal)) {
      rejected.push({ template, reason: 'Sink path resolves outside the assessed source tree.' });
      continue;
    }
    const relativeSink = path.relative(root, sinkReal);
    let sinkMatches: ExploreSearchMatch[];
    let allMatches: ExploreSearchMatch[];
    try {
      sinkMatches = parseJsonMatches(await runRipgrep(root, template.regex, relativeSink), root, template);
      if (!sinkMatches.some((match) => match.match_line === template.sink_line)) {
        rejected.push({ template, reason: 'The supplied regex does not match the recorded sink line.' });
        continue;
      }
      allMatches = parseJsonMatches(await runRipgrep(root, template.regex), root, template);
    } catch (error) {
      rejected.push({ template, reason: error instanceof Error ? error.message : 'Search failed.' });
      continue;
    }
    for (const match of allMatches) {
      // The seed itself is provenance, not a newly discovered location.
      if (match.match_file === template.sink_file && match.match_line === template.sink_line) continue;
      matches.push(match);
      if (matches.length >= MAX_TOTAL_MATCHES) break;
      if (matches.filter((entry) => entry.finding_id === template.finding_id && entry.regex === template.regex).length >= MAX_MATCHES_PER_TEMPLATE) break;
    }
    if (matches.length >= MAX_TOTAL_MATCHES) break;
  }
  const unique = new Map<string, ExploreSearchMatch>();
  for (const match of matches) unique.set(`${match.finding_id}:${match.match_file}:${match.match_line}`, match);
  return { matches: [...unique.values()], rejected };
}
