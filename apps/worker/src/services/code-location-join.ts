// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/** Join analysis and SAST locations from committed report-facing tasks without mixing location lanes. */

import type { QueueCodeLocation } from '../ai/queue-schemas.js';
import type { SastSourceLocation } from '../ai/reconciliation/contracts.js';
import type { AddFindingInput } from '../collectors/finding-collector.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import { ALL_VULN_CLASSES } from '../types/config.js';
import { ErrorCode } from '../types/errors.js';
import type { ReconciliationClass } from '../types/reconciliation.js';
import { PentestError } from './error-handling.js';
import { readCommittedFile } from './git-manager.js';
import { renumberMapPath } from './renumber-core.js';

interface QueueEntry {
  ID?: string;
  code_locations?: QueueCodeLocation[];
  sast_source_location?: SastSourceLocation;
}

interface JoinedLocations {
  readonly codeLocations?: QueueCodeLocation[];
  readonly sastSourceLocation?: SastSourceLocation;
}

interface LocationIndexes {
  readonly stable: ReadonlyMap<string, JoinedLocations>;
  readonly current: ReadonlyMap<string, JoinedLocations>;
}

function mergeCodeLocations(
  existing: readonly QueueCodeLocation[] | undefined,
  additions: readonly QueueCodeLocation[],
): QueueCodeLocation[] {
  const unique = new Map<string, QueueCodeLocation>();
  for (const location of [...(existing ?? []), ...additions]) {
    unique.set(JSON.stringify(location), location);
  }
  return [...unique.values()];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isQueueCodeLocation(value: unknown): value is QueueCodeLocation {
  if (!isRecord(value) || typeof value.file !== 'string' || value.file.length === 0) return false;
  if (!['sink', 'source', 'guard'].includes(String(value.role))) return false;
  if (value.start_line !== undefined && (!Number.isInteger(value.start_line) || (value.start_line as number) < 1))
    return false;
  if (value.end_line !== undefined && (!Number.isInteger(value.end_line) || (value.end_line as number) < 1))
    return false;
  if (
    Number.isInteger(value.start_line) &&
    Number.isInteger(value.end_line) &&
    (value.end_line as number) < (value.start_line as number)
  )
    return false;
  return value.symbol === undefined || typeof value.symbol === 'string';
}

// The queue entry is untrusted committed JSON, not a value this process just produced, so its
// shape is re-validated field by field rather than trusted from the type annotation alone.
function isSastSourceLocation(value: unknown): value is SastSourceLocation {
  if (!isRecord(value)) return false;
  return (
    typeof value.file === 'string' &&
    value.file.length > 0 &&
    Number.isInteger(value.line) &&
    (value.line as number) > 0 &&
    Number.isInteger(value.column) &&
    (value.column as number) >= 0 &&
    typeof value.rule_id === 'string' &&
    value.rule_id.length > 0
  );
}

function committedLocationError(
  message: string,
  checkCode: string,
  vulnerabilityClass: ReconciliationClass,
): PentestError {
  return new PentestError(
    message,
    'validation',
    false,
    { checkCode, vulnerabilityClass },
    ErrorCode.AGENT_EXECUTION_FAILED,
  );
}

function parseJson(contents: string, description: string, vulnerabilityClass: ReconciliationClass): unknown {
  try {
    return JSON.parse(contents) as unknown;
  } catch {
    throw committedLocationError(
      `${description} is not valid JSON`,
      'committed-location-json-invalid',
      vulnerabilityClass,
    );
  }
}

async function currentReferenceMap(
  deliverablesPath: string,
  vulnerabilityClass: ReconciliationClass,
): Promise<ReadonlyMap<string, string>> {
  const mapRead = await readCommittedFile(deliverablesPath, renumberMapPath(vulnerabilityClass));
  if (mapRead.state === 'absent') return new Map();
  if (mapRead.state !== 'present') {
    throw committedLocationError(
      `${vulnerabilityClass} report-reference map is unreadable`,
      'committed-reference-map-unreadable',
      vulnerabilityClass,
    );
  }
  const decoded = parseJson(mapRead.contents, `${vulnerabilityClass} report-reference map`, vulnerabilityClass);
  if (!isRecord(decoded) || !isRecord(decoded.map)) {
    throw committedLocationError(
      `${vulnerabilityClass} report-reference map is malformed`,
      'committed-reference-map-malformed',
      vulnerabilityClass,
    );
  }
  const references = new Map<string, string>();
  for (const [stable, current] of Object.entries(decoded.map)) {
    if (typeof current !== 'string') {
      throw committedLocationError(
        `${vulnerabilityClass} report-reference map is malformed`,
        'committed-reference-map-entry-malformed',
        vulnerabilityClass,
      );
    }
    references.set(stable, current);
  }
  return references;
}

async function loadQueueLocations(
  deliverablesPath: string,
  participatingClasses: readonly ReconciliationClass[],
): Promise<LocationIndexes> {
  const stableLocations = new Map<string, JoinedLocations>();
  const currentLocations = new Map<string, JoinedLocations>();
  for (const vulnerabilityClass of participatingClasses) {
    const referenceMap = await currentReferenceMap(deliverablesPath, vulnerabilityClass);
    const queues = [
      { path: `${vulnerabilityClass}_exploitation_queue.json`, applyReferenceMap: true },
      { path: `explore_candidates_${vulnerabilityClass}.json`, applyReferenceMap: false },
    ];
    for (const queue of queues) {
      const queueRead = await readCommittedFile(deliverablesPath, queue.path);
      if (queueRead.state === 'absent') continue;
      if (queueRead.state !== 'present') {
        throw committedLocationError(`${queue.path} is unreadable`, 'committed-queue-unreadable', vulnerabilityClass);
      }
      const decoded = parseJson(queueRead.contents, queue.path, vulnerabilityClass);
      if (!isRecord(decoded) || !Array.isArray(decoded.vulnerabilities)) {
        throw committedLocationError(`${queue.path} is malformed`, 'committed-queue-malformed', vulnerabilityClass);
      }
      for (const rawEntry of decoded.vulnerabilities) {
        if (!isRecord(rawEntry) || typeof rawEntry.ID !== 'string') continue;
        const stableReference = rawEntry.ID;
        const entry = rawEntry as QueueEntry;
        const codeLocations = Array.isArray(entry.code_locations)
          ? entry.code_locations.filter(isQueueCodeLocation)
          : [];
        const bundle: JoinedLocations = {
          ...(codeLocations.length > 0 ? { codeLocations } : {}),
          ...(isSastSourceLocation(entry.sast_source_location)
            ? { sastSourceLocation: entry.sast_source_location }
            : {}),
        };
        if (bundle.codeLocations === undefined && bundle.sastSourceLocation === undefined) continue;
        stableLocations.set(stableReference, bundle);
        if (queue.applyReferenceMap) {
          const currentReference = referenceMap.get(stableReference);
          if (currentReference !== undefined) currentLocations.set(currentReference, bundle);
        }
      }
    }

    const expansionPath = `explore_expansion_${vulnerabilityClass}.json`;
    const expansionRead = await readCommittedFile(deliverablesPath, expansionPath);
    if (expansionRead.state === 'corrupt') {
      throw committedLocationError(
        `${expansionPath} is unreadable`,
        'committed-expansion-unreadable',
        vulnerabilityClass,
      );
    }
    if (expansionRead.state === 'present') {
      const expansion = parseJson(expansionRead.contents, expansionPath, vulnerabilityClass);
      if (!isRecord(expansion) || !Array.isArray(expansion.assessments)) {
        throw committedLocationError(
          `${expansionPath} is malformed`,
          'committed-expansion-malformed',
          vulnerabilityClass,
        );
      }
      for (const assessment of expansion.assessments) {
        if (
          !isRecord(assessment) ||
          typeof assessment.finding_id !== 'string' ||
          !Array.isArray(assessment.confirmed_code_locations)
        )
          continue;
        const additions = assessment.confirmed_code_locations.filter((location): location is QueueCodeLocation =>
          isQueueCodeLocation(location),
        );
        if (additions.length === 0) continue;
        const existing = stableLocations.get(assessment.finding_id);
        const merged: JoinedLocations = {
          ...existing,
          codeLocations: mergeCodeLocations(existing?.codeLocations, additions),
        };
        stableLocations.set(assessment.finding_id, merged);
        const currentReference = referenceMap.get(assessment.finding_id);
        if (currentReference !== undefined) currentLocations.set(currentReference, merged);
      }
    }
  }
  return { stable: stableLocations, current: currentLocations };
}

/** Attach the two independent location fields without consulting exploit-inspection locations. */
export async function attachQueueCodeLocations(
  findings: readonly AddFindingInput[],
  deliverablesPath: string,
  logger: ActivityLogger,
  participatingClasses: readonly ReconciliationClass[] = ALL_VULN_CLASSES,
): Promise<AddFindingInput[]> {
  const byReference = await loadQueueLocations(deliverablesPath, participatingClasses);
  let analysisMatches = 0;
  let sastMatches = 0;
  const joined = findings.map((finding) => {
    // Report findings normally carry the renumbered current reference. Resolve that lane first,
    // then fall back to the stable lane for unrenumbered classes. Keeping the lanes separate
    // prevents one entry's stable reference from overwriting another entry's current reference.
    const locations = byReference.current.get(finding.finding_id) ?? byReference.stable.get(finding.finding_id);
    if (locations?.codeLocations !== undefined) analysisMatches++;
    if (locations?.sastSourceLocation !== undefined) sastMatches++;
    // The queue is the sole authority for sast_source_location: strip any value the finding
    // carries so it is present iff Capella committed one, never a report-agent fabrication.
    const { sast_source_location: _dropped, ...withoutSast } = finding;
    return {
      ...withoutSast,
      ...(locations?.codeLocations !== undefined && { code_locations: locations.codeLocations }),
      ...(locations?.sastSourceLocation !== undefined && { sast_source_location: locations.sastSourceLocation }),
    };
  });
  logger.info('Attached committed report-task locations', {
    findings: findings.length,
    analysisMatches,
    sastMatches,
  });
  return joined;
}
