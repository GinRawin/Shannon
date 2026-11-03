/** File names for the isolated Explore-expansion queues. */

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

export function isExpansionVulnQueueFilename(filename: string | undefined): boolean {
  return filename !== undefined && /^explore_expansion_[a-z]+_vuln_queue\.json$/.test(filename);
}
