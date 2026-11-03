/** File names for the isolated Explore-expansion queues. */

import { REF_PREFIX } from '../ai/reconciliation/refs.js';
import type { ReconciliationClass } from '../types/reconciliation.js';

export function expansionVulnQueueFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_vuln_queue.json`;
}

export function expansionAnalysisFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_analysis_deliverable.md`;
}

export function expansionExploitQueueFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_exploit_queue.json`;
}

export function expansionCollectorFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_exploit_collector.json`;
}

export function expansionEvidenceFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_exploitation_evidence.md`;
}

export function expansionRecordedEvidenceFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_recorded_exploitation_evidence.md`;
}

export function expansionReportFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}.md`;
}

export function expansionSubmissionAuditFilename(vulnerabilityClass: ReconciliationClass): string {
  return `explore_expansion_${vulnerabilityClass}_submission_audit.json`;
}

export function nextExpansionExploitTaskNumber(
  vulnerabilityClass: ReconciliationClass,
  existingFindingIds: Iterable<string>,
): number {
  const pattern = new RegExp(`^${REF_PREFIX[vulnerabilityClass]}-(\\d+)$`);
  let maximum = 0;
  for (const id of existingFindingIds) {
    const match = pattern.exec(id);
    if (match !== null) maximum = Math.max(maximum, Number(match[1]));
  }
  return maximum + 1;
}

export function expansionExploitTaskId(vulnerabilityClass: ReconciliationClass, taskNumber: number): string {
  return `${REF_PREFIX[vulnerabilityClass]}-${String(taskNumber).padStart(2, '0')}`;
}
