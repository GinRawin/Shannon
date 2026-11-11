// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-agent git path scoping.
 *
 * Under parallel agent execution the deliverables git is shared, so each agent's
 * checkpoint/commit/rollback must be limited to the files that agent actually
 * writes. This resolves those paths from the agent's deliverable filename plus
 * its structured exploitation queue (vuln agents only).
 */

import { getQueueFilename } from '../ai/queue-schemas.js';
import { REPORT_JSON_FILENAME } from '../paths.js';
import { AGENTS } from '../session-manager.js';
import {
  expansionAnalysisFilename,
  expansionExploitQueueFilename,
  expansionSubmissionAuditFilename,
  expansionVulnQueueFilename,
} from './expansion-queues.js';
import type { AgentName } from '../types/agents.js';
import type { ReconciliationClass } from '../types/reconciliation.js';

// These names must match `sparseExploitCollectorPath` in renumber-core.ts, which derives the
// same filename from the bare ReconciliationClass at read time. If the two fall out of sync,
// git scoping silently drops the collector file from an agent's checkpoint/commit/rollback set:
// the file sits uncommitted in the working tree, or is not restored on rollback, with neither
// side raising an error.
const EXPLOIT_COLLECTOR_PATHS: Readonly<Partial<Record<AgentName, string>>> = Object.freeze({
  'injection-exploit': 'injection_exploit_collector.json',
  'xss-exploit': 'xss_exploit_collector.json',
  'auth-exploit': 'auth_exploit_collector.json',
  'ssrf-exploit': 'ssrf_exploit_collector.json',
  'authz-exploit': 'authz_exploit_collector.json',
  'miscellaneous-exploit': 'miscellaneous_exploit_collector.json',
});

/**
 * Deliverable files an agent writes into the deliverables directory. Used to
 * scope git operations so one agent never touches a sibling agent's output.
 */
export function getAgentGitPaths(agentName: AgentName, queueFilenameOverride?: string): string[] {
  const paths = [AGENTS[agentName].deliverableFilename];
  const queueFilename = queueFilenameOverride ?? getQueueFilename(agentName);
  if (queueFilename) {
    paths.push(queueFilename);
  }
  const exploitCollectorPath = EXPLOIT_COLLECTOR_PATHS[agentName];
  if (exploitCollectorPath !== undefined) {
    paths.push(exploitCollectorPath);
    paths.push(`exploit_review_${agentName.replace(/-exploit$/, '')}.json`);
  }
  // The report agent owns only its provisional markdown input and structured JSON. Canonical
  // Markdown/SARIF ownership transfers to the finalization transaction after report completion.
  if (agentName === 'report') {
    paths.push(REPORT_JSON_FILENAME);
  }
  if (agentName === 'record') {
    paths.push(
      'record_verification.json',
      'record_verified_finding_ids.json',
      'record_report_exclusions.json',
      'record-failures.json',
      'record-verification-failures.jsonl',
      'http-exchanges',
      'http-replay-verifications',
      'browser-replay-verifications',
    );
    const recordClasses: ReconciliationClass[] = [
      'injection',
      'xss',
      'auth',
      'ssrf',
      'authz',
      'miscellaneous',
    ];
    for (const vulnerabilityClass of recordClasses) {
      paths.push(
        `exploit_review_${vulnerabilityClass}.json`,
        `${vulnerabilityClass}_recorded_exploitation_evidence.md`,
        `${vulnerabilityClass}_exploitation_evidence.md`,
        `${vulnerabilityClass}_exploit_collector.json`,
        `${vulnerabilityClass}_exploit_collector_renumbered.json`,
        `${vulnerabilityClass}_exploitation_queue.json`,
        `${vulnerabilityClass}_renumber_map.json`,
      );
      paths.push(
        `explore_candidates_${vulnerabilityClass}.json`,
        `explore_expansion_${vulnerabilityClass}.md`,
        expansionAnalysisFilename(vulnerabilityClass),
        expansionVulnQueueFilename(vulnerabilityClass),
        expansionExploitQueueFilename(vulnerabilityClass),
        expansionSubmissionAuditFilename(vulnerabilityClass),
        `explore_expansion_${vulnerabilityClass}_exploit_collector.json`,
        `explore_expansion_${vulnerabilityClass}_exploitation_evidence.md`,
        `explore_expansion_${vulnerabilityClass}_recorded_exploitation_evidence.md`,
      );
    }
  }
  if (agentName === 'explore') {
    paths.push('explore_search_results.json', 'explore_seeds.json', 'explore_clone_coverage.json');
  }
  const vulnExpansionArtifacts: Readonly<Partial<Record<AgentName, string>>> = {
    'injection-vuln': 'explore_expansion_injection.json',
    'xss-vuln': 'explore_expansion_xss.json',
    'auth-vuln': 'explore_expansion_auth.json',
    'ssrf-vuln': 'explore_expansion_ssrf.json',
    'authz-vuln': 'explore_expansion_authz.json',
  };
  const expansionArtifact = vulnExpansionArtifacts[agentName];
  if (expansionArtifact) {
    paths.push(expansionArtifact);
    const vulnerabilityClass = agentName.replace(/-vuln$/, '') as ReconciliationClass;
    paths.push(
      `explore_expansion_${vulnerabilityClass}.md`,
      `explore_candidates_${vulnerabilityClass}.json`,
      expansionAnalysisFilename(vulnerabilityClass),
      expansionVulnQueueFilename(vulnerabilityClass),
      expansionExploitQueueFilename(vulnerabilityClass),
      expansionSubmissionAuditFilename(vulnerabilityClass),
    );
  }
  const exploitExpansionClass: Readonly<Partial<Record<AgentName, string>>> = {
    'injection-exploit': 'injection',
    'xss-exploit': 'xss',
    'auth-exploit': 'auth',
    'ssrf-exploit': 'ssrf',
    'authz-exploit': 'authz',
  };
  const expansionClass = exploitExpansionClass[agentName];
  if (expansionClass) {
    paths.push(
      `explore_expansion_${expansionClass}.md`,
      `explore_expansion_${expansionClass}_exploit_collector.json`,
      `explore_expansion_${expansionClass}_exploitation_evidence.md`,
    );
  }
  return [...new Set(paths)];
}
