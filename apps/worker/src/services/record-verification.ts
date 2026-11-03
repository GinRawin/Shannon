import fs from 'node:fs/promises';
import path from 'node:path';
import type { AddExploitInput } from '../collectors/exploit-collector.js';
import type { RecordVerdict } from '../collectors/record-collector.js';
import { atomicWrite } from '../utils/file-io.js';
import { type BrowserReplayPlan, hasTrustedBrowserReplay } from './browser-replay.js';
import { renderExploitDeliverable } from './exploit-renderer.js';
import { expansionExploitQueueFilename } from './expansion-queues.js';
import { loadPacketBackedFindingIds } from './http-evidence.js';
import type { HttpReplayPlan } from './http-replay.js';

export const RECORD_CLASSES = ['injection', 'xss', 'auth', 'ssrf', 'authz', 'miscellaneous'] as const;
export type RecordClass = (typeof RECORD_CLASSES)[number];

export interface RecordFailure {
  finding_id: string;
  vulnerability_class: RecordClass;
  title: string;
  severity: string;
  source_collector: string | null;
  renumbered_collector: string | null;
  source_entry: Record<string, unknown> | null;
  renumbered_entry: Record<string, unknown> | null;
  exploit_log_path: string | null;
  original_http_replay: HttpReplayPlan | null;
  variable_requirements: Record<string, unknown>;
  record_attempts: Array<Record<string, unknown>>;
  existing_evidence: string[];
  missing_evidence: string[];
  failure_source: 'record' | 'record-expansion' | 'record-retry';
}

export interface ExploitReviewResult {
  finding_id: string;
  verdict: 'false_positive' | 'retry';
  reason: string;
  revised_http_replay?: HttpReplayPlan;
  revised_browser_replay?: BrowserReplayPlan;
  variable_requirements?: Record<string, unknown>;
  record_instructions?: string[];
  expected_evidence?: Record<string, unknown>;
}

/** Validate browser screenshots and optionally require evidence created during the current retry. */
export async function validateRecordBrowserEvidence(
  repoPath: string,
  files: readonly string[],
  notBefore?: number,
): Promise<string[]> {
  const scratchpad = path.join(repoPath, '.shannon', 'scratchpad');
  const realScratchpad = await fs.realpath(scratchpad).catch(() => {
    throw new Error('The workspace scratchpad directory does not exist.');
  });
  const validated: string[] = [];
  for (const file of files) {
    const segments = file.split('/');
    if (
      segments.length < 3 ||
      segments[0] !== '.shannon' ||
      segments[1] !== 'scratchpad' ||
      segments.some((segment) => !segment || segment === '.' || segment === '..' || segment.includes('\\'))
    )
      throw new Error('Browser evidence files must be workspace-relative paths under .shannon/scratchpad/.');
    if (!/\.(?:png|jpe?g|webp)$/i.test(file))
      throw new Error('Browser verification requires screenshot evidence in PNG, JPEG, or WebP format.');
    const fullPath = path.resolve(repoPath, ...segments);
    const realPath = await fs.realpath(fullPath).catch(() => {
      throw new Error(`Browser screenshot does not exist: ${file}`);
    });
    if (!realPath.startsWith(`${realScratchpad}${path.sep}`))
      throw new Error('Browser screenshot resolves outside the workspace scratchpad.');
    const stat = await fs.stat(realPath);
    if (!stat.isFile() || stat.size === 0 || stat.size > 20 * 1024 * 1024)
      throw new Error(`Browser screenshot is empty or exceeds the 20 MiB evidence limit: ${file}`);
    if (notBefore !== undefined && stat.mtimeMs < notBefore)
      throw new Error(`Browser screenshot predates this Record retry attempt: ${file}`);
    validated.push(file);
  }
  return validated;
}

async function readArray(file: string): Promise<Array<Record<string, unknown>>> {
  try {
    const value: unknown = JSON.parse(await fs.readFile(file, 'utf8'));
    return Array.isArray(value)
      ? value.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
      : [];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

export function mergeRecordVerdicts(...sets: ReadonlyArray<readonly RecordVerdict[]>): RecordVerdict[] {
  const merged = new Map<string, RecordVerdict>();
  for (const verdict of sets.flat()) {
    const previous = merged.get(verdict.finding_id);
    if (previous?.status === 'verified' && verdict.status === 'failed') continue;
    merged.set(verdict.finding_id, verdict);
  }
  return [...merged.values()].sort((left, right) => left.finding_id.localeCompare(right.finding_id));
}

export async function aggregateRecordFailures(
  deliverablesDir: string,
  exploitLogPaths: ReadonlyMap<string, string> = new Map(),
): Promise<RecordFailure[]> {
  const verdicts = (await readArray(
    path.join(deliverablesDir, 'record_verification.json'),
  )) as unknown as RecordVerdict[];
  const failures: RecordFailure[] = [];
  for (const verdict of mergeRecordVerdicts(verdicts).filter((item) => item.status === 'failed')) {
    let matched:
      | Omit<RecordFailure, 'record_attempts' | 'existing_evidence' | 'missing_evidence' | 'failure_source'>
      | undefined;
    for (const vulnerabilityClass of RECORD_CLASSES) {
      const sourceNames = [
        `${vulnerabilityClass}_exploit_collector.json`,
        `explore_expansion_${vulnerabilityClass}_exploit_collector.json`,
      ];
      for (const sourceName of sourceNames) {
        const source = (await readArray(path.join(deliverablesDir, sourceName))).find(
          (entry) => entry.vulnerability_id === verdict.finding_id,
        );
        if (!source) continue;
        const renumberedName = sourceName.startsWith('explore_')
          ? sourceName
          : `${vulnerabilityClass}_exploit_collector_renumbered.json`;
        let renumbered = source;
        if (renumberedName !== sourceName) {
          const mapFile = path.join(deliverablesDir, `${vulnerabilityClass}_renumber_map.json`);
          let finalId = verdict.finding_id;
          try {
            const map = JSON.parse(await fs.readFile(mapFile, 'utf8')) as { map?: Record<string, string> };
            finalId = map.map?.[verdict.finding_id] ?? finalId;
          } catch {
            /* source ID remains stable when no renumber map exists */
          }
          renumbered =
            (await readArray(path.join(deliverablesDir, renumberedName))).find(
              (entry) => entry.vulnerability_id === finalId,
            ) ?? source;
        }
        matched = {
          finding_id: verdict.finding_id,
          vulnerability_class: vulnerabilityClass,
          title: String(source.title ?? verdict.finding_id),
          severity: String(source.severity ?? 'unknown'),
          source_collector: sourceName,
          renumbered_collector: renumberedName,
          source_entry: source,
          renumbered_entry: renumbered,
          exploit_log_path:
            typeof source.exploit_log_path === 'string'
              ? source.exploit_log_path
              : (exploitLogPaths.get(
                  sourceName.startsWith('explore_') ? `${vulnerabilityClass}-expansion` : vulnerabilityClass,
                ) ?? null),
          original_http_replay:
            source.http_replay && typeof source.http_replay === 'object'
              ? (source.http_replay as unknown as HttpReplayPlan)
              : null,
          variable_requirements:
            source.variable_requirements && typeof source.variable_requirements === 'object'
              ? (source.variable_requirements as Record<string, unknown>)
              : {},
        };
        break;
      }
      if (matched) break;
    }
    failures.push({
      ...(matched ?? {
        finding_id: verdict.finding_id,
        vulnerability_class: 'miscellaneous' as const,
        title: verdict.finding_id,
        severity: 'unknown',
        source_collector: null,
        renumbered_collector: null,
        source_entry: null,
        renumbered_entry: null,
        exploit_log_path: null,
        original_http_replay: null,
        variable_requirements: {},
      }),
      record_attempts: verdict.replay_history?.length
        ? verdict.replay_history.map((attempt) => ({
            ...attempt,
            attempts: 1,
            error: attempt.error ?? verdict.error ?? verdict.reason,
            partial_capture_ids: attempt.capture_ids,
          }))
        : [
            {
              attempts: verdict.attempts ?? 0,
              failure_kind: verdict.failure_kind ?? 'verification_failed',
              error: verdict.error ?? verdict.reason,
              partial_capture_ids: verdict.partial_capture_ids ?? verdict.capture_ids,
              variable_diagnostics: verdict.variable_diagnostics ?? [],
              record_log_path: verdict.record_log_path ?? '',
              stage: verdict.stage ?? 'record',
            },
          ],
      existing_evidence: verdict.capture_ids,
      missing_evidence: [
        ...(verdict.capture_ids.length ? [] : ['complete_http_packet']),
        ...(matched?.vulnerability_class === 'xss' && !verdict.browser_verification ? ['javascript_execution'] : []),
      ],
      failure_source: verdict.stage ?? 'record',
    });
  }
  await atomicWrite(path.join(deliverablesDir, 'record-failures.json'), `${JSON.stringify(failures, null, 2)}\n`);
  return failures;
}

async function removeIdsFromQueue(file: string, ids: ReadonlySet<string>): Promise<void> {
  try {
    const document = JSON.parse(await fs.readFile(file, 'utf8')) as { vulnerabilities?: Array<{ ID?: unknown }> };
    if (!Array.isArray(document.vulnerabilities)) return;
    document.vulnerabilities = document.vulnerabilities.filter(
      (item) => typeof item.ID !== 'string' || !ids.has(item.ID),
    );
    await atomicWrite(file, `${JSON.stringify(document, null, 2)}\n`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

/** Apply review decisions without renumbering surviving findings, preserving stable report IDs. */
export async function applyExploitReviews(
  deliverablesDir: string,
  reviews: readonly ExploitReviewResult[],
): Promise<void> {
  const falsePositiveIds = new Set(
    reviews.filter((item) => item.verdict === 'false_positive').map((item) => item.finding_id),
  );
  if (!falsePositiveIds.size) return;
  const removedReportIds = new Set<string>();
  for (const vulnerabilityClass of RECORD_CLASSES) {
    const mapPath = path.join(deliverablesDir, `${vulnerabilityClass}_renumber_map.json`);
    const mappedFinalIds = new Set<string>();
    const mappedSourceIds = new Set<string>();
    try {
      const map = JSON.parse(await fs.readFile(mapPath, 'utf8')) as { map?: Record<string, string> };
      for (const id of falsePositiveIds) {
        const reportId = map.map?.[id];
        if (reportId) {
          removedReportIds.add(reportId);
          mappedSourceIds.add(id);
          mappedFinalIds.add(reportId);
        }
      }
      if (map.map) {
        for (const id of falsePositiveIds) delete map.map[id];
        await atomicWrite(mapPath, `${JSON.stringify(map, null, 2)}\n`);
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    for (const name of [
      `${vulnerabilityClass}_exploit_collector.json`,
      `${vulnerabilityClass}_exploit_collector_renumbered.json`,
      `explore_expansion_${vulnerabilityClass}_exploit_collector.json`,
    ]) {
      const file = path.join(deliverablesDir, name);
      const entries = await readArray(file);
      if (!entries.length) continue;
      if (name.startsWith('explore_expansion_')) {
        for (const entry of entries)
          if (typeof entry.vulnerability_id === 'string' && falsePositiveIds.has(entry.vulnerability_id))
            removedReportIds.add(entry.vulnerability_id);
      } else if (name === `${vulnerabilityClass}_exploit_collector.json`) {
        for (const entry of entries)
          if (
            typeof entry.vulnerability_id === 'string' &&
            falsePositiveIds.has(entry.vulnerability_id) &&
            !mappedSourceIds.has(entry.vulnerability_id)
          )
            removedReportIds.add(entry.vulnerability_id);
      }
      const idsToRemove =
        name === `${vulnerabilityClass}_exploit_collector_renumbered.json`
          ? mappedFinalIds.size
            ? mappedFinalIds
            : falsePositiveIds
          : falsePositiveIds;
      const filtered = entries.filter(
        (entry) => typeof entry.vulnerability_id !== 'string' || !idsToRemove.has(entry.vulnerability_id),
      );
      if (filtered.length !== entries.length) await atomicWrite(file, `${JSON.stringify(filtered, null, 2)}\n`);
    }
    await removeIdsFromQueue(
      path.join(deliverablesDir, `${vulnerabilityClass}_exploitation_queue.json`),
      falsePositiveIds,
    );
    await removeIdsFromQueue(
      path.join(deliverablesDir, `explore_candidates_${vulnerabilityClass}.json`),
      falsePositiveIds,
    );
    await removeIdsFromQueue(
      path.join(deliverablesDir, expansionExploitQueueFilename(vulnerabilityClass)),
      falsePositiveIds,
    );
  }
  const verdicts = (await readArray(
    path.join(deliverablesDir, 'record_verification.json'),
  )) as unknown as RecordVerdict[];
  await atomicWrite(
    path.join(deliverablesDir, 'record_verification.json'),
    `${JSON.stringify(
      verdicts.filter((item) => !falsePositiveIds.has(item.finding_id)),
      null,
      2,
    )}\n`,
  );
  try {
    const verified: unknown = JSON.parse(
      await fs.readFile(path.join(deliverablesDir, 'record_verified_finding_ids.json'), 'utf8'),
    );
    if (Array.isArray(verified)) {
      await atomicWrite(
        path.join(deliverablesDir, 'record_verified_finding_ids.json'),
        `${JSON.stringify(
          verified.filter((id): id is string => typeof id === 'string' && !removedReportIds.has(id)),
          null,
          2,
        )}\n`,
      );
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

export async function writeFinalRecordFailureAudit(
  deliverablesDir: string,
  runId: string,
  failures: readonly RecordFailure[],
  reviews: readonly ExploitReviewResult[],
): Promise<void> {
  const reviewById = new Map(reviews.map((review) => [review.finding_id, review]));
  const lines = failures.map((failure) => {
    const review = reviewById.get(failure.finding_id);
    return JSON.stringify({
      timestamp: new Date().toISOString(),
      run_id: runId,
      finding_id: failure.finding_id,
      vulnerability_class: failure.vulnerability_class,
      attempts: failure.record_attempts.reduce((count, item) => count + Number(item.attempts ?? 0), 0),
      last_failure: failure.record_attempts.at(-1) ?? null,
      review_verdict: review?.verdict ?? null,
      review_reason: review?.reason ?? null,
      original_replay_plan: failure.original_http_replay,
      revised_replay_plan: review?.revised_http_replay ?? null,
      original_browser_replay: failure.source_entry?.browser_replay ?? null,
      revised_browser_replay: review?.revised_browser_replay ?? null,
      record_log_path: failure.record_attempts.at(-1)?.record_log_path ?? null,
      exploit_log_path: failure.exploit_log_path,
      report_blocked: false,
      report_excluded: true,
    });
  });
  await atomicWrite(
    path.join(deliverablesDir, 'record-verification-failures.jsonl'),
    `${lines.join('\n')}${lines.length ? '\n' : ''}`,
  );
}

export interface RecordReportExclusion {
  finding_id: string;
  report_finding_id: string;
  vulnerability_class: RecordClass;
  source_collector: string;
  reasons: string[];
}

/** Keep source IDs and report IDs in their own namespaces, including in exclusion manifests. */
async function recordReportCandidates(deliverablesDir: string): Promise<RecordReportExclusion[]> {
  const verdicts = (await readArray(
    path.join(deliverablesDir, 'record_verification.json'),
  )) as unknown as RecordVerdict[];
  const verdictById = new Map(mergeRecordVerdicts(verdicts).map((verdict) => [verdict.finding_id, verdict]));
  const packetBackedIds = await loadPacketBackedFindingIds(deliverablesDir);
  const failures: RecordReportExclusion[] = [];
  for (const vulnerabilityClass of RECORD_CLASSES) {
    const source = await readArray(path.join(deliverablesDir, `${vulnerabilityClass}_exploit_collector.json`));
    let map: Record<string, string> = {};
    try {
      map =
        (
          JSON.parse(
            await fs.readFile(path.join(deliverablesDir, `${vulnerabilityClass}_renumber_map.json`), 'utf8'),
          ) as { map?: Record<string, string> }
        ).map ?? {};
    } catch {
      /* absent class */
    }
    const expansion = await readArray(
      path.join(deliverablesDir, `explore_expansion_${vulnerabilityClass}_exploit_collector.json`),
    );
    for (const [entries, expanded] of [
      [source, false],
      [expansion, true],
    ] as const) {
      for (const entry of entries) {
        if (entry.status !== 'exploited' || typeof entry.vulnerability_id !== 'string') continue;
        const verdict = verdictById.get(entry.vulnerability_id);
        const finalId = expanded ? entry.vulnerability_id : (map[entry.vulnerability_id] ?? entry.vulnerability_id);
        const reasons: string[] = [];
        if (verdict?.status !== 'verified') reasons.push('missing verified Record verdict');
        if (!packetBackedIds.has(finalId)) reasons.push('missing complete associated HTTP packet');
        if (
          vulnerabilityClass === 'xss' &&
          (JSON.stringify([...(verdict?.capture_ids ?? [])].sort()) !==
            JSON.stringify([...((entry.http_evidence_ids as string[]) ?? [])].sort()) ||
            !(await hasTrustedBrowserReplay({
              deliverablesDir,
              findingId: entry.vulnerability_id,
              stage: verdict?.stage,
              plan: entry.browser_replay as BrowserReplayPlan | undefined,
              verification: verdict?.browser_verification,
              httpCaptureIds: verdict?.capture_ids ?? [],
            })))
        )
          reasons.push('missing JavaScript execution evidence');
        failures.push({
          finding_id: entry.vulnerability_id,
          report_finding_id: finalId,
          vulnerability_class: vulnerabilityClass,
          source_collector: expanded
            ? `explore_expansion_${vulnerabilityClass}_exploit_collector.json`
            : `${vulnerabilityClass}_exploit_collector.json`,
          reasons,
        });
      }
    }
  }
  return failures;
}

export async function validateRecordReportAdmission(deliverablesDir: string): Promise<string[]> {
  const exclusions = await readArray(path.join(deliverablesDir, 'record_report_exclusions.json'));
  const failures = await recordReportCandidates(deliverablesDir);
  return failures
    .filter(
      (failure) =>
        !exclusions.some(
          (exclusion) =>
            exclusion.finding_id === failure.finding_id &&
            exclusion.report_finding_id === failure.report_finding_id &&
            exclusion.source_collector === failure.source_collector,
        ),
    )
    .flatMap((failure) => failure.reasons.map((reason) => `${failure.report_finding_id}: ${reason}`))
    .sort();
}

/** Recheck the actual proof as well as the allowlist before the report collector accepts an ID. */
export async function loadRecordReportFindingIds(deliverablesDir: string): Promise<ReadonlySet<string>> {
  const exclusions = await readArray(path.join(deliverablesDir, 'record_report_exclusions.json'));
  return new Set(
    (await recordReportCandidates(deliverablesDir))
      .filter(
        (candidate) =>
          candidate.reasons.length === 0 &&
          !exclusions.some(
            (exclusion) =>
              exclusion.finding_id === candidate.finding_id &&
              exclusion.report_finding_id === candidate.report_finding_id &&
              exclusion.source_collector === candidate.source_collector,
          ),
      )
      .map((candidate) => candidate.report_finding_id),
  );
}

/** Finalize the bounded replay loop without relabeling unresolved findings as false positives. */
export async function finalizeRecordReportAdmission(deliverablesDir: string): Promise<RecordReportExclusion[]> {
  const candidates = await recordReportCandidates(deliverablesDir);
  const exclusions = candidates.filter((candidate) => candidate.reasons.length > 0);
  const verified = candidates
    .filter((candidate) => candidate.reasons.length === 0)
    .map((candidate) => candidate.report_finding_id);
  await atomicWrite(
    path.join(deliverablesDir, 'record_report_exclusions.json'),
    `${JSON.stringify(exclusions, null, 2)}\n`,
  );
  await atomicWrite(
    path.join(deliverablesDir, 'record_verified_finding_ids.json'),
    `${JSON.stringify([...new Set(verified)].sort(), null, 2)}\n`,
  );
  await refreshRecordedReportEvidence(deliverablesDir);
  return exclusions;
}

/** Update a retry proof only in the ID namespace of each artifact. */
export async function applyRecordRetryEvidence(
  deliverablesDir: string,
  verdicts: readonly RecordVerdict[],
  plans: ReadonlyMap<string, HttpReplayPlan>,
  browserPlans: ReadonlyMap<string, BrowserReplayPlan> = new Map(),
): Promise<string[]> {
  const verified = new Set<string>();
  for (const vulnerabilityClass of RECORD_CLASSES) {
    let idMap: Record<string, string> = {};
    try {
      idMap =
        (
          JSON.parse(
            await fs.readFile(path.join(deliverablesDir, `${vulnerabilityClass}_renumber_map.json`), 'utf8'),
          ) as { map?: Record<string, string> }
        ).map ?? {};
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    for (const [name, renumbered, expanded] of [
      [`${vulnerabilityClass}_exploit_collector.json`, false, false],
      [`${vulnerabilityClass}_exploit_collector_renumbered.json`, true, false],
      [`explore_expansion_${vulnerabilityClass}_exploit_collector.json`, false, true],
    ] as const) {
      const file = path.join(deliverablesDir, name);
      const entries = await readArray(file);
      let changed = false;
      for (const verdict of verdicts) {
        if (verdict.status !== 'verified') continue;
        const id = renumbered ? (idMap[verdict.finding_id] ?? verdict.finding_id) : verdict.finding_id;
        const entry = entries.find((item) => item.vulnerability_id === id);
        if (!entry) continue;
        Object.assign(entry, {
          http_evidence_ids: verdict.capture_ids,
          http_evidence_receipts: verdict.http_evidence_receipts ?? [],
          http_evidence_display: 'include',
          verification_method: verdict.browser_verification ? 'mixed' : 'http',
          http_evidence_reason: verdict.reason,
          http_replay: plans.get(verdict.finding_id),
          http_replay_verification: verdict.http_replay_verification,
        });
        if (verdict.browser_verification) {
          entry.browser_replay = browserPlans.get(verdict.finding_id);
          entry.browser_verification = verdict.browser_verification;
          entry.browser_evidence_files = verdict.browser_verification.evidence_files;
        }
        if (renumbered || expanded) verified.add(id);
        changed = true;
      }
      if (changed) await atomicWrite(file, `${JSON.stringify(entries, null, 2)}\n`);
    }
  }
  return [...verified];
}

/** Report inputs contain only findings admitted by the final Record decision. */
export async function refreshRecordedReportEvidence(deliverablesDir: string): Promise<string[]> {
  const ids: unknown = JSON.parse(
    await fs.readFile(path.join(deliverablesDir, 'record_verified_finding_ids.json'), 'utf8'),
  );
  if (!Array.isArray(ids) || ids.some((id) => typeof id !== 'string')) throw new Error('Invalid Record allowlist.');
  const verified = new Set(ids as string[]);
  const verdicts = (await readArray(
    path.join(deliverablesDir, 'record_verification.json'),
  )) as unknown as RecordVerdict[];
  const written: string[] = [];
  for (const vulnerabilityClass of RECORD_CLASSES) {
    let idMap: Record<string, string> = {};
    try {
      idMap =
        (
          JSON.parse(
            await fs.readFile(path.join(deliverablesDir, `${vulnerabilityClass}_renumber_map.json`), 'utf8'),
          ) as { map?: Record<string, string> }
        ).map ?? {};
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    const originalId = new Map(Object.entries(idMap).map(([source, final]) => [final, source]));
    for (const expanded of [false, true]) {
      const name = expanded
        ? `explore_expansion_${vulnerabilityClass}_exploit_collector.json`
        : `${vulnerabilityClass}_exploit_collector_renumbered.json`;
      const entries = await readArray(path.join(deliverablesDir, name));
      if (
        !entries.length &&
        !(await fs.access(path.join(deliverablesDir, name)).then(
          () => true,
          () => false,
        ))
      )
        continue;
      const admitted = entries.filter(
        (entry) => typeof entry.vulnerability_id === 'string' && verified.has(entry.vulnerability_id),
      );
      let markdown = renderExploitDeliverable(vulnerabilityClass, admitted as AddExploitInput[], new Map());
      for (const entry of admitted) {
        const id = String(entry.vulnerability_id);
        const sourceId = expanded ? id : (originalId.get(id) ?? id);
        const verdict = verdicts.find((item) => item.finding_id === sourceId);
        if (verdict)
          markdown += `\n\nRecord ${id}: ${verdict.reason}\n\nFrontend: ${verdict.frontend_status} — ${verdict.frontend_url ?? ''} ${verdict.frontend_trigger ?? verdict.frontend_reason}\n`;
      }
      const filenames = expanded
        ? [
            `explore_expansion_${vulnerabilityClass}_recorded_exploitation_evidence.md`,
            `explore_expansion_${vulnerabilityClass}.md`,
          ]
        : [`${vulnerabilityClass}_recorded_exploitation_evidence.md`];
      for (const filename of filenames) {
        await atomicWrite(path.join(deliverablesDir, filename), markdown);
        written.push(filename);
      }
    }
  }
  return written;
}
