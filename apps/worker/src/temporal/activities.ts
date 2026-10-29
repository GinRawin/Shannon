// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal activities for Shannon agent execution.
 *
 * Each activity wraps service calls with Temporal-specific concerns:
 * - Heartbeat loop (2s interval) to signal worker liveness
 * - Error classification into ApplicationFailure
 * - Container lifecycle management
 *
 * Business logic is delegated to services in src/services/.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { ApplicationFailure, Context, heartbeat } from '@temporalio/activity';
import { syncPermissionSystemConfig } from '../ai/pi/permission-system.js';
import { writePlaywrightStealthConfig } from '../ai/playwright-config-writer.js';
import { AuditSession } from '../audit/index.js';
import type { ResumeAttempt } from '../audit/metrics-tracker.js';
import type { LoggableAgentName, WorkflowPhase } from '../audit/safe-fields.js';
import { authStateFile, generateAuditPath, type SessionMetadata } from '../audit/utils.js';
import type { WorkflowSummary } from '../audit/workflow-logger.js';
import type { CheckpointContext } from '../interfaces/checkpoint-provider.js';
import {
  ASSEMBLED_REPORT_PDF_FILENAME,
  DEFAULT_DELIVERABLES_SUBDIR,
  deliverablesDir,
  REPORT_FINALIZATION_MANIFEST_FILENAME,
  REPORT_JSON_FILENAME,
  resolveSessionJsonPath,
  TYPST_TEMPLATE,
} from '../paths.js';
import { getAgentGitPaths } from '../services/agent-git-paths.js';
import { compactReportFindings as compactReportFindingsService } from '../services/compaction-core.js';
import { getContainer, getOrCreateContainer, removeContainer } from '../services/container.js';
import { classifyErrorForTemporal, PentestError } from '../services/error-handling.js';
import { RenumberError, writeAndCommitExactFiles } from '../services/exact-output-commit.js';
import { ExploitationCheckerService } from '../services/exploitation-checker.js';
import { candidateMatchesExploreSearch, locationMatchesExploreSearch } from '../services/explore-search.js';
import { renderFindingsFromQueues } from '../services/findings-renderer.js';
import { executeGitCommandWithRetry } from '../services/git-manager.js';
import { attachHttpEvidence, configuredCaptureRedactions, writeReproductionScript } from '../services/http-evidence.js';
import { pdfProvenanceIsCurrent } from '../services/pdf-renderer.js';
import {
  PostExploitationReplayRequiredError,
  runPostExploitationPass,
  validatePostExploitationCheckpoint,
} from '../services/post-exploitation.js';
import { runPreflightChecks } from '../services/preflight.js';
import { formatVulnClassScope, loadPromptFragment } from '../services/prompt-manager.js';
import type { ExploitationDecision, VulnType } from '../services/queue-validation.js';
import {
  renumberClassFindings as renumberClassFindingsService,
  sparseExploitCollectorPath,
} from '../services/renumber-core.js';
import {
  checkpointFileContents,
  checkpointIsAncestor,
  draftProgressIsCoherent,
  finalProgressIsCoherent,
  readFileAtCheckpoint,
  reportCheckpointIsCoherent,
  resolveCheckpointCommit,
  validateDraftProgress,
} from '../services/report-checkpoints.js';
import {
  finalizeReport,
  ReportFinalizationIntegrityError,
  ReportSarifRenderError,
} from '../services/report-finalization.js';
import { surfaceReportOutputs as surfaceReportOutputsService } from '../services/report-output-surface.js';
import type { ReportData, ReportMeta } from '../services/report-renderer.js';
import { assembleFinalReportWithEvidence } from '../services/reporting.js';
import { validateAuthentication } from '../services/validate-authentication.js';
import { AGENTS } from '../session-manager.js';
import type { AgentName } from '../types/agents.js';
import type { ContainerConfig, VulnClass } from '../types/config.js';
import { ErrorCode } from '../types/errors.js';
import type { PostExploitationStage } from '../types/post-exploitation.js';
import type { ReconciliationClass } from '../types/reconciliation.js';
import { isErr } from '../types/result.js';
import {
  appendPartialReasons,
  assertFixedAnalysisScope,
  type DurableScanState,
  FIXED_ANALYSIS_CLASSES,
  initialExpectedAgents,
  isDurableScanState,
  isOrderedPartialReasonSet,
  isReportProgress,
  type MiscellaneousOutcome,
  type PartialReason,
  type ReportProgress,
  type ReportSarifDisposition,
  RunStateError,
  SAFE_RUN_STATE_MESSAGES,
  type StoredPdfProvenance,
  workspaceExploitMismatchMessage,
} from '../types/run-state.js';
import { atomicWrite, fileExists, readJson } from '../utils/file-io.js';
import { createActivityLogger } from './activity-logger.js';
import type {
  AgentMetrics,
  AssembleReportActivityResult,
  DurableStateSummary,
  FinalizeReportActivityResult,
  PipelineState,
  ReconciliationActivityResult,
  ResumeState,
  SurfaceReportActivityResult,
} from './shared.js';

// Max lengths to prevent Temporal protobuf buffer overflow
const MAX_ERROR_MESSAGE_LENGTH = 2000;
const MAX_STACK_TRACE_LENGTH = 1000;

// Max retries for output validation errors (agent didn't save deliverables)
const MAX_OUTPUT_VALIDATION_RETRIES = 3;

const HEARTBEAT_INTERVAL_MS = 2000;

/**
 * Input for all agent activities.
 *
 * Config fields are optional with sensible defaults. When provided, they
 * flow through to getOrCreateContainer() for path configuration.
 */
export interface ActivityInput {
  webUrl: string;
  repoPath: string;
  /** Workflow-owned UTC date for every customer-facing assessment date. */
  assessmentDate?: string;
  configPath?: string;
  outputPath?: string;
  pipelineTestingMode?: boolean;
  workflowId: string;
  sessionId: string;

  // Config fields — serializable, read by getOrCreateContainer()
  configYAML?: string;
  deliverablesSubdir?: string;
  auditDir?: string;
  promptDir?: string;
  sastSarifPath?: string;

  /** Fixed workflow-resolved scope supplied to every agent prompt. */
  analysisClasses?: readonly VulnClass[];
  /** Distinguishes absent state on a fresh run from forbidden resume reconstruction. */
  stateContext?: 'fresh' | 'resume';
  /** Operational route label; no customer path crosses workflow history. */
  customerOutputRoute?: 'workspace' | 'mounted';

  // Vuln classes whose pipeline failed. Set before the report stage on a partial run so the
  // report marks them "not assessed" instead of asserting no findings were present.
  failedClasses?: VulnClass[];
  /** Set only for the single targeted analysis pass driven by Explore matches. */
  exploreExpansion?: boolean;
}

/**
 * Truncate error message to prevent buffer overflow in Temporal serialization.
 */
function truncateErrorMessage(message: string): string {
  if (message.length <= MAX_ERROR_MESSAGE_LENGTH) {
    return message;
  }
  return `${message.slice(0, MAX_ERROR_MESSAGE_LENGTH - 20)}\n[truncated]`;
}

/**
 * Truncate stack trace on an ApplicationFailure to prevent buffer overflow.
 */
function truncateStackTrace(failure: ApplicationFailure): void {
  if (failure.stack && failure.stack.length > MAX_STACK_TRACE_LENGTH) {
    failure.stack = `${failure.stack.slice(0, MAX_STACK_TRACE_LENGTH)}\n[stack truncated]`;
  }
}

/**
 * Build SessionMetadata from ActivityInput.
 */
function buildSessionMetadata(input: ActivityInput): SessionMetadata {
  const { webUrl, repoPath, outputPath, sessionId } = input;
  return {
    id: sessionId,
    webUrl,
    repoPath,
    ...(outputPath && { outputPath }),
  };
}

/**
 * Build ContainerConfig from ActivityInput, falling back to defaults.
 */
function buildContainerConfig(input: ActivityInput): ContainerConfig {
  return {
    deliverablesSubdir: input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
    auditDir: input.auditDir ?? './workspaces',
    ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
  };
}

/**
 * Classify a failure from durable scan-state persistence. A RunStateError already carries a
 * caller-safe message and code, so it maps directly; anything else reaches this path without
 * having touched durable state, so it falls back to the generic activity classifier.
 */
function runStateFailure(error: unknown): ApplicationFailure {
  if (error instanceof RunStateError) {
    return ApplicationFailure.nonRetryable(error.message, error.failureType, [{ checkCode: error.checkCode }]);
  }
  const classified = classifyErrorForTemporal(error);
  const message = 'Durable execution-state persistence failed.';
  return classified.retryable
    ? ApplicationFailure.create({ message, type: classified.type })
    : ApplicationFailure.nonRetryable(message, classified.type);
}

/** Stable Temporal types for the two declared renumber corruption modes. */
const RENUMBER_STABLE_FAILURE_TYPES = Object.freeze({
  'unmappable-survivor': 'UnmappableSurvivor',
  'key-set-divergence': 'KeySetDivergence',
} as const satisfies Record<RenumberError['type'], string>);

/**
 * Classify a failure from a deterministic report-processing activity (renumber, compaction,
 * finalization). Each underlying service throws its own typed error so the workflow can react
 * to the specific stage that broke; this is the one place that maps those types onto stable
 * Temporal failure names, so the mapping cannot drift between call sites.
 */
function deterministicActivityFailure(error: unknown, failureType: string): ApplicationFailure {
  if (error instanceof RunStateError) return runStateFailure(error);
  if (error instanceof ReportSarifRenderError) {
    // The workflow invokes degraded finalization only after this exact retryable type
    // exhausts the activity policy, so the name must survive the boundary unflattened.
    return ApplicationFailure.create({
      message: error.message,
      type: 'ReportSarifRenderError',
      nonRetryable: false,
      details: [{ stage: failureType }],
    });
  }
  if (error instanceof ReportFinalizationIntegrityError) {
    return ApplicationFailure.nonRetryable(error.message, 'ReportFinalizationIntegrityError', [
      { checkCode: error.checkCode },
    ]);
  }
  if (error instanceof RenumberError) {
    const details = [
      {
        ...(error.details?.checkCode !== undefined && { checkCode: error.details.checkCode }),
        ...(error.details?.vulnerabilityClass !== undefined && {
          vulnerabilityClass: error.details.vulnerabilityClass,
        }),
      },
    ];
    const stableType = RENUMBER_STABLE_FAILURE_TYPES[error.type];
    return error.retryable
      ? ApplicationFailure.create({ message: error.message, type: stableType, details })
      : ApplicationFailure.nonRetryable(error.message, stableType, details);
  }
  const classified = classifyErrorForTemporal(error);
  const message = 'Deterministic report processing failed.';
  return classified.retryable
    ? ApplicationFailure.create({ message, type: failureType })
    : ApplicationFailure.nonRetryable(message, failureType);
}

/**
 * The five analysis classes are fixed for a scan's whole lifetime and resolved once by the
 * workflow so every agent prompt sees the same scope. An activity invoked without that scope
 * is a caller bug rather than a transient condition, so it fails without a retry.
 */
function resolveAnalysisClasses(input: ActivityInput): readonly VulnClass[] {
  if (input.analysisClasses === undefined) {
    throw ApplicationFailure.nonRetryable(
      'Workflow-resolved analysis scope is required.',
      'IncompatibleWorkspaceError',
      [{ checkCode: 'analysis-scope-missing' }],
    );
  }
  try {
    assertFixedAnalysisScope(input.analysisClasses);
  } catch (error) {
    throw runStateFailure(error);
  }
  return input.analysisClasses;
}

/** Project only the fields the workflow needs to update its queryable state, out of the full durable record. */
function durableStateSummary(state: DurableScanState): DurableStateSummary {
  return {
    exploit: state.exploit,
    expectedAgents: [...state.expected_agents],
    participatingClasses: [...state.participating_classes],
    reportStage: state.report?.stage ?? 'uninitialized',
    ...(state.miscellaneous_outcome !== undefined && { miscellaneousOutcome: state.miscellaneous_outcome }),
  };
}

function sha256(contents: string): string {
  return createHash('sha256').update(contents, 'utf8').digest('hex');
}

function arraysEqual<T>(left: readonly T[], right: readonly T[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

async function rollbackInvalidReportDraft(input: ActivityInput, progress: ReportProgress): Promise<void> {
  if (progress.stage !== 'draft') {
    throw new RunStateError('CorruptedSessionError', 'invalid-nondraft-report-progress');
  }
  const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  // Transient resolution failures throw for retry; only proven absence or corruption of the
  // draft parent is treated as corrupted workspace state.
  const parentCheckpoint = await resolveCheckpointCommit(deliverablesPath, `${progress.model_checkpoint}^`);
  if (parentCheckpoint === null) {
    throw new RunStateError('CorruptedSessionError', 'report-draft-parent-unavailable');
  }

  for (const relPath of getAgentGitPaths('report')) {
    const prior = await readFileAtCheckpoint(deliverablesPath, parentCheckpoint, relPath);
    if (prior.state === 'corrupt') {
      throw new RunStateError('CorruptedSessionError', 'report-draft-parent-corrupt');
    }
    if (prior.state === 'absent') {
      await executeGitCommandWithRetry(
        ['git', 'rm', '--cached', '--ignore-unmatch', '--', relPath],
        deliverablesPath,
        'unstage invalid report draft path',
      );
      await fs.unlink(path.join(deliverablesPath, relPath)).catch((error: unknown) => {
        if (!(error instanceof Error && (error as NodeJS.ErrnoException).code === 'ENOENT')) throw error;
      });
      continue;
    }
    await executeGitCommandWithRetry(
      ['git', 'restore', `--source=${parentCheckpoint}`, '--staged', '--worktree', '--', relPath],
      deliverablesPath,
      'restore invalid report draft path',
    );
  }

  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  await auditSession.rollbackReportDraft();
}

/**
 * Core activity implementation using services.
 *
 * Executes a single agent with:
 * 1. Heartbeat loop for worker liveness
 * 2. Container creation/reuse
 * 3. Service-based agent execution
 * 4. Error classification for Temporal retry
 *
 * `successDisposition` tells the service what "done" means for this agent: ordinary agents
 * commit a terminal deliverable, while the report agent instead produces a draft that still
 * needs canonical checkpointing before it is finished. `allowCheckpointSkip` is false only for
 * the report agent, whose skip decision belongs to the durable report-progress state machine
 * rather than the generic checkpoint provider used by every other agent.
 */
async function runAgentActivity(
  agentName: AgentName,
  input: ActivityInput,
  customTools?: import('@earendil-works/pi-coding-agent').ToolDefinition[],
  writeDeliverable?: (deliverablesPath: string, execution: { readonly model?: string }) => Promise<void>,
  successDisposition: 'terminal' | 'report-draft' = 'terminal',
  allowCheckpointSkip = true,
  promptAddendum?: string,
  auditAgentName?: LoggableAgentName,
): Promise<AgentMetrics> {
  const { repoPath, configPath, pipelineTestingMode = false, workflowId, webUrl } = input;

  // Skip guard: the checkpoint provider decides whether to run the agent.
  // The default NoOp provider always returns { skip: false }.
  const skipContainer =
    getContainer(workflowId) ??
    getOrCreateContainer(workflowId, buildSessionMetadata(input), buildContainerConfig(input));
  if (allowCheckpointSkip) {
    const decision = await skipContainer.checkpointProvider.shouldSkipAgent(
      agentName,
      repoPath,
      input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
    );
    if (decision.skip && decision.metrics) {
      return { ...decision.metrics, skipped: true };
    }
  }

  const startTime = Date.now();
  const attemptNumber = Context.current().info.attempt;

  // Heartbeat loop - signals worker is alive to Temporal server
  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ agent: agentName, elapsedSeconds: elapsed, attempt: attemptNumber });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const logger = createActivityLogger();

    // 1. Build session metadata and get/create container
    const sessionMetadata = buildSessionMetadata(input);
    const container = getOrCreateContainer(workflowId, sessionMetadata, buildContainerConfig(input));

    // 2. Create audit session for THIS agent execution
    // NOTE: Each agent needs its own AuditSession because AuditSession uses
    // instance state (currentAgentName) that cannot be shared across parallel agents
    const auditSession = new AuditSession(sessionMetadata);
    await auditSession.initialize(workflowId);

    // 3. Execute agent via service (throws PentestError on failure)
    const deliverablesPath = deliverablesDir(repoPath, container.config.deliverablesSubdir);
    const endResult = await container.agentExecution.executeOrThrow(
      agentName,
      {
        webUrl,
        repoPath,
        deliverablesPath,
        configPath,
        pipelineTestingMode,
        attemptNumber,
        assessmentDate: input.assessmentDate,
        analysisClasses: resolveAnalysisClasses(input),
        ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
        ...(input.configYAML !== undefined && { configYAML: input.configYAML }),
        ...(input.failedClasses !== undefined && { failedClasses: input.failedClasses }),
        ...(customTools && { customTools }),
        ...(writeDeliverable && { writeDeliverable }),
        ...(promptAddendum !== undefined && { promptAddendum }),
        ...(auditAgentName !== undefined && { auditAgentName }),
        successDisposition,
        cancellationSignal: Context.current().cancellationSignal,
      },
      auditSession,
      logger,
    );

    // 4. Return metrics
    return {
      durationMs: Date.now() - startTime,
      inputTokens: endResult.input_tokens ?? null,
      outputTokens: endResult.output_tokens ?? null,
      cacheReadTokens: endResult.cache_read_tokens ?? null,
      cacheWriteTokens: endResult.cache_write_tokens ?? null,
      costUsd: endResult.cost_usd,
      numTurns: endResult.turns ?? null,
      model: endResult.model,
      ...(endResult.checkpoint !== undefined && { checkpoint: endResult.checkpoint }),
    };
  } catch (error) {
    // If error is already an ApplicationFailure, re-throw directly
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    // Check if output validation retry limit reached (PentestError with code)
    if (
      error instanceof PentestError &&
      error.code === ErrorCode.OUTPUT_VALIDATION_FAILED &&
      attemptNumber >= MAX_OUTPUT_VALIDATION_RETRIES
    ) {
      throw ApplicationFailure.nonRetryable(
        `Agent ${agentName} failed output validation after ${attemptNumber} attempts`,
        'OutputValidationError',
        [{ agentName, attemptNumber, elapsed: Date.now() - startTime }],
      );
    }

    // Classify error for Temporal retry behavior
    const classified = classifyErrorForTemporal(error);
    const rawMessage = error instanceof Error ? error.message : String(error);
    const message = truncateErrorMessage(rawMessage);

    if (classified.retryable) {
      const failure = ApplicationFailure.create({
        message,
        type: classified.type,
        details: [{ agentName, attemptNumber, elapsed: Date.now() - startTime }],
      });
      truncateStackTrace(failure);
      throw failure;
    } else {
      const failure = ApplicationFailure.nonRetryable(message, classified.type, [
        { agentName, attemptNumber, elapsed: Date.now() - startTime },
      ]);
      truncateStackTrace(failure);
      throw failure;
    }
  } finally {
    clearInterval(heartbeatInterval);
  }
}

export async function runPreReconAgent(input: ActivityInput): Promise<AgentMetrics> {
  const { createPreReconCollector } = await import('../collectors/pre-recon-collector.js');
  const { renderPreRecon } = await import('../services/pre-recon-renderer.js');

  const collector = createPreReconCollector();

  const writeDeliverable = async (deliverablesPath: string): Promise<void> => {
    const logger = createActivityLogger();
    // Skipped tools surface as renderer placeholders, not as activity failures.
    const callStatus = collector.getCallStatus();
    logger.info('Pre-recon tool call status', { callStatus });

    const collected = collector.getAll();
    const markdown = renderPreRecon(collected);
    const mdPath = path.join(deliverablesPath, 'pre_recon_deliverable.md');
    await atomicWrite(mdPath, markdown);
    logger.info(`Wrote pre_recon_deliverable.md from structured data (${markdown.length} bytes)`);
  };

  return runAgentActivity('pre-recon', input, collector.tools, writeDeliverable);
}

export async function runReconAgent(input: ActivityInput): Promise<AgentMetrics> {
  const { createReconCollector } = await import('../collectors/recon-collector.js');
  const { renderRecon } = await import('../services/recon-renderer.js');

  const collector = createReconCollector();

  const writeDeliverable = async (deliverablesPath: string): Promise<void> => {
    const logger = createActivityLogger();
    // Skipped tools surface as renderer placeholders, not as activity failures.
    const callStatus = collector.getCallStatus();
    logger.info('Recon tool call status', { callStatus });

    const collected = collector.getAll();
    const markdown = renderRecon(collected);
    const mdPath = path.join(deliverablesPath, 'recon_deliverable.md');
    await atomicWrite(mdPath, markdown);
    logger.info(`Wrote recon_deliverable.md from structured data (${markdown.length} bytes)`);
  };

  return runAgentActivity('recon', input, collector.tools, writeDeliverable);
}

async function runVulnAgentWithCollector(
  agentName: 'injection-vuln' | 'xss-vuln' | 'auth-vuln' | 'ssrf-vuln' | 'authz-vuln',
  vulnClass: 'injection' | 'xss' | 'auth' | 'ssrf' | 'authz',
  input: ActivityInput,
): Promise<AgentMetrics> {
  const { createVulnCollector } = await import('../collectors/vuln-collector.js');
  const { renderVulnDeliverable } = await import('../services/vuln-renderer.js');

  const expansionPath = path.join(
    deliverablesDir(input.repoPath, input.deliverablesSubdir),
    `explore_expansion_${vulnClass}.json`,
  );
  let expansionTargets: Array<{
    finding_id: string;
    producer_id: string;
    vulnerability: Record<string, unknown>;
    matches: Array<{ match_file: string; match_line: number; excerpt: string; regex: string }>;
  }> = [];
  let originalQueueContents: string | undefined;
  let originalAnalysisContents: string | undefined;
  let priorQueueDocument: { vulnerabilities?: Array<Record<string, unknown> & { ID?: string }> } = {};
  const priorProducerIds = new Set<string>();
  if (input.exploreExpansion) {
    const dir = deliverablesDir(input.repoPath, input.deliverablesSubdir);
    const clearStaleExpansion = async (): Promise<void> => {
      await writeAndCommitExactFiles(
        dir,
        [
          { relPath: `explore_expansion_${vulnClass}.json`, contents: null },
          { relPath: `explore_expansion_${vulnClass}.md`, contents: null },
          { relPath: `explore_candidates_${vulnClass}.json`, contents: null },
        ],
        `Clear stale ${vulnClass} exploration`,
        createActivityLogger(),
      );
    };
    const results = JSON.parse(await fs.readFile(path.join(dir, 'explore_search_results.json'), 'utf8')) as {
      matches?: Array<{
        finding_id: string;
        vulnerability_class: string;
        match_file: string;
        match_line: number;
        excerpt: string;
        regex: string;
      }>;
    };
    const classMatches = (results.matches ?? []).filter((match) => match.vulnerability_class === vulnClass);
    if (!classMatches.length) {
      await clearStaleExpansion();
      return {
        durationMs: 0,
        inputTokens: null,
        outputTokens: null,
        cacheReadTokens: null,
        cacheWriteTokens: null,
        costUsd: 0,
        numTurns: 0,
        skipped: true,
      };
    }
    const [manifestRaw, exploitCollectorRaw, priorQueue, priorAnalysis] = await Promise.all([
      fs.readFile(path.join(dir, `${vulnClass}_reconciliation_manifest.json`), 'utf8'),
      fs.readFile(path.join(dir, `${vulnClass}_exploit_collector_renumbered.json`), 'utf8'),
      fs.readFile(path.join(dir, `${vulnClass}_exploitation_queue.json`), 'utf8'),
      fs.readFile(path.join(dir, `${vulnClass}_analysis_deliverable.md`), 'utf8').catch(() => ''),
    ]);
    originalQueueContents = priorQueue;
    originalAnalysisContents = priorAnalysis;
    const manifest = JSON.parse(manifestRaw) as { lineage?: Record<string, { primary?: string; absorbed?: string[] }> };
    priorQueueDocument = JSON.parse(priorQueue) as {
      vulnerabilities?: Array<Record<string, unknown> & { ID?: string }>;
    };
    const exploitEntries = JSON.parse(exploitCollectorRaw) as Array<
      Record<string, unknown> & { vulnerability_id?: string }
    >;
    const entryById = new Map(exploitEntries.map((entry) => [entry.vulnerability_id, entry]));
    const grouped = new Map<string, typeof classMatches>();
    for (const match of classMatches) grouped.set(match.finding_id, [...(grouped.get(match.finding_id) ?? []), match]);
    const producerPrefix: Record<typeof vulnClass, string> = {
      injection: 'INJ',
      xss: 'XSS',
      auth: 'AUTH',
      ssrf: 'SSRF',
      authz: 'AUTHZ',
    };
    const lineageIds = Object.values(manifest.lineage ?? {}).flatMap((entry) => [
      entry.primary,
      ...(entry.absorbed ?? []),
    ]);
    for (const lineageId of lineageIds) {
      if (lineageId !== undefined) priorProducerIds.add(lineageId);
    }
    const producerIdPattern = new RegExp(`^${producerPrefix[vulnClass]}-VULN-(\\d+)$`);
    let nextExpansionId =
      lineageIds.reduce((max, id) => {
        const number = producerIdPattern.exec(id ?? '')?.[1];
        return number ? Math.max(max, Number(number)) : max;
      }, 0) + 1;
    expansionTargets = [...grouped.entries()].flatMap(([findingId, matches]) => {
      const vulnerability = entryById.get(findingId);
      if (!manifest.lineage?.[findingId] || !vulnerability) return [];
      const producerId = `${producerPrefix[vulnClass]}-VULN-${String(nextExpansionId++).padStart(2, '0')}`;
      return [{ finding_id: findingId, producer_id: producerId, vulnerability, matches }];
    });
    if (!expansionTargets.length) {
      await clearStaleExpansion();
      return {
        durationMs: 0,
        inputTokens: null,
        outputTokens: null,
        cacheReadTokens: null,
        cacheWriteTokens: null,
        costUsd: 0,
        numTurns: 0,
        skipped: true,
      };
    }
  }

  const collector = createVulnCollector(vulnClass);

  const writeDeliverable = async (deliverablesPath: string): Promise<void> => {
    const logger = createActivityLogger();
    // Skipped tools surface as renderer placeholders, not as activity failures.
    const callStatus = collector.getCallStatus();
    logger.info(`${vulnClass} vuln tool call status`, { callStatus });

    const collected = collector.getAll();
    const markdown = renderVulnDeliverable(vulnClass, collected);
    const mdPath = path.join(deliverablesPath, `${vulnClass}_analysis_deliverable.md`);
    await atomicWrite(mdPath, markdown);
    logger.info(`Wrote ${vulnClass}_analysis_deliverable.md from structured data (${markdown.length} bytes)`);
    if (input.exploreExpansion) {
      const queuePath = path.join(deliverablesPath, `${vulnClass}_exploitation_queue.json`);
      let submitted: Array<Record<string, unknown>> = [];
      try {
        const parsed = JSON.parse(await fs.readFile(queuePath, 'utf8')) as { vulnerabilities?: unknown };
        if (Array.isArray(parsed.vulnerabilities))
          submitted = parsed.vulnerabilities.filter(
            (entry): entry is Record<string, unknown> => !!entry && typeof entry === 'object',
          );
      } catch {
        /* an absent submission yields no expansion assessments */
      }
      const targetsByProducer = new Map(expansionTargets.map((target) => [target.producer_id, target]));
      const allExpansionMatches = expansionTargets.flatMap((target) => target.matches);
      const unboundIndependentProducers = submitted.filter(
        (entry) => typeof entry.ID === 'string' && !targetsByProducer.has(entry.ID) && !priorProducerIds.has(entry.ID),
      );
      const independentProducers = unboundIndependentProducers.filter((entry) =>
        candidateMatchesExploreSearch(entry, allExpansionMatches),
      );
      const usedTaskIds = new Set(
        (priorQueueDocument.vulnerabilities ?? [])
          .map((entry) => entry.ID)
          .filter((id): id is string => typeof id === 'string'),
      );
      const idPrefix: Record<typeof vulnClass, string> = {
        injection: 'INJ',
        xss: 'XSS',
        auth: 'AUTH',
        ssrf: 'SSRF',
        authz: 'AUTHZ',
      };
      const idPattern = new RegExp(`^${idPrefix[vulnClass]}-(\\d+)$`);
      let nextTaskId = [...usedTaskIds].reduce((max, id) => Math.max(max, Number(idPattern.exec(id)?.[1] ?? 0)), 0) + 1;
      const independentCandidates: Array<Record<string, unknown> & { ID: string }> = independentProducers.map(
        (entry) => {
          const { ID: _producerId, ...candidate } = entry;
          return { ...candidate, ID: `${idPrefix[vulnClass]}-${String(nextTaskId++).padStart(2, '0')}` };
        },
      );
      const assessments = submitted.flatMap((entry) => {
        const target = typeof entry.ID === 'string' ? targetsByProducer.get(entry.ID) : undefined;
        if (!target) return [];
        const locations = Array.isArray(entry.code_locations)
          ? entry.code_locations.filter(
              (location) =>
                !!location &&
                typeof location === 'object' &&
                locationMatchesExploreSearch(
                  location as { file?: unknown; start_line?: unknown; end_line?: unknown },
                  target.matches,
                ),
            )
          : [];
        if (!locations.length) return [];
        return [
          {
            finding_id: target.finding_id,
            producer_id: target.producer_id,
            title: typeof entry.title === 'string' ? entry.title : target.vulnerability.title,
            assessment: [
              'verdict',
              'mismatch_reason',
              'missing_defense',
              'exploitation_hypothesis',
              'guard_evidence',
              'reason',
              'notes',
            ]
              .flatMap((key) => (typeof entry[key] === 'string' ? [`${key}: ${entry[key]}`] : []))
              .join('; '),
            matched_locations: target.matches.map((match) => ({
              file: match.match_file,
              line: match.match_line,
              excerpt: match.excerpt,
            })),
            confirmed_code_locations: locations,
          },
        ];
      });
      const inputDigest = createHash('sha256').update(JSON.stringify(expansionTargets)).digest('hex');
      const candidateQueuePath = path.join(deliverablesPath, `explore_candidates_${vulnClass}.json`);
      await atomicWrite(candidateQueuePath, `${JSON.stringify({ vulnerabilities: independentCandidates }, null, 2)}\n`);
      await atomicWrite(
        expansionPath,
        `${JSON.stringify(
          {
            vulnerability_class: vulnClass,
            input_digest: inputDigest,
            assessments,
            independent_candidates: independentCandidates,
            rejected_unbound_candidate_count: unboundIndependentProducers.length - independentProducers.length,
          },
          null,
          2,
        )}\n`,
      );
      const expansionLines = [
        `# Template-based expansion review: ${vulnClass}`,
        '',
        'The following independent candidates run through a dedicated exploit and record pass. Reporting requires either replay-verified impact or source-confirmed impact validation blocked by a documented external condition. Related locations under an existing finding ID only enrich that finding.',
        '',
        '## Independently confirmed additional findings',
        '',
      ];
      for (const candidate of independentCandidates) {
        const locations = Array.isArray(candidate.code_locations)
          ? candidate.code_locations.filter(
              (location): location is Record<string, unknown> =>
                !!location && typeof location === 'object' && typeof (location as { file?: unknown }).file === 'string',
            )
          : [];
        const renderedLocations = locations.map((location) => {
          const start = Number.isInteger(location.start_line) ? `:${String(location.start_line)}` : '';
          const end =
            Number.isInteger(location.end_line) && location.end_line !== location.start_line
              ? `-${String(location.end_line)}`
              : '';
          const role = typeof location.role === 'string' ? ` (${location.role})` : '';
          return `${String(location.file)}${start}${end}${role}`;
        });
        expansionLines.push(
          `- Independent candidate ${String(candidate.ID)}: ${String(candidate.title ?? candidate.vulnerability_type ?? 'Untitled')}`,
          ...(renderedLocations.length > 0 ? [`  - Confirmed source locations: ${renderedLocations.join(', ')}`] : []),
        );
      }
      for (const item of assessments) {
        expansionLines.push(`## ${item.finding_id}: ${item.title ?? 'Related code location'}`, '');
        for (const location of item.confirmed_code_locations as Array<{
          file?: string;
          start_line?: number;
          end_line?: number;
        }>)
          expansionLines.push(
            `- Confirmed related location: ${location.file}${location.start_line ? `:${location.start_line}` : ''}${location.end_line && location.end_line !== location.start_line ? `-${location.end_line}` : ''}`,
          );
        if (item.assessment) expansionLines.push(`- Analysis: ${String(item.assessment)}`);
        expansionLines.push('');
      }
      await atomicWrite(
        path.join(deliverablesPath, `explore_expansion_${vulnClass}.md`),
        `${expansionLines.join('\n')}\n`,
      );
      if (originalQueueContents !== undefined) await atomicWrite(queuePath, originalQueueContents);
      if (originalAnalysisContents !== undefined) {
        await atomicWrite(
          path.join(deliverablesPath, `${vulnClass}_analysis_deliverable.md`),
          originalAnalysisContents,
        );
      }
    }
  };
  let promptAddendum: string | undefined;
  if (input.exploreExpansion) {
    const instructions = await loadPromptFragment(
      'explore-expansion',
      input.pipelineTestingMode ?? false,
      createActivityLogger(),
      input.promptDir,
    );
    promptAddendum = `${instructions}\n\n${JSON.stringify({ targets: expansionTargets }, null, 2)}\n</template_expansion_pass>`;
  }
  try {
    const auditAgentName = input.exploreExpansion
      ? (`${vulnClass}-vuln-expansion` as PostExploitationStage)
      : undefined;
    return await runAgentActivity(
      agentName,
      input,
      collector.tools,
      writeDeliverable,
      'terminal',
      !input.exploreExpansion,
      promptAddendum,
      auditAgentName,
    );
  } finally {
    if (input.exploreExpansion) {
      const dir = deliverablesDir(input.repoPath, input.deliverablesSubdir);
      if (originalQueueContents !== undefined)
        await atomicWrite(path.join(dir, `${vulnClass}_exploitation_queue.json`), originalQueueContents);
      if (originalAnalysisContents !== undefined)
        await atomicWrite(path.join(dir, `${vulnClass}_analysis_deliverable.md`), originalAnalysisContents);
    }
  }
}

export async function runInjectionVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('injection-vuln', 'injection', input);
}

export async function runXssVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('xss-vuln', 'xss', input);
}

export async function runAuthVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('auth-vuln', 'auth', input);
}

export async function runSsrfVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('ssrf-vuln', 'ssrf', input);
}

export async function runAuthzVulnAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('authz-vuln', 'authz', input);
}

export async function runInjectionVulnExpansionAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('injection-vuln', 'injection', { ...input, exploreExpansion: true });
}

export async function runXssVulnExpansionAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('xss-vuln', 'xss', { ...input, exploreExpansion: true });
}

export async function runAuthVulnExpansionAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('auth-vuln', 'auth', { ...input, exploreExpansion: true });
}

export async function runSsrfVulnExpansionAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('ssrf-vuln', 'ssrf', { ...input, exploreExpansion: true });
}

export async function runAuthzVulnExpansionAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runVulnAgentWithCollector('authz-vuln', 'authz', { ...input, exploreExpansion: true });
}

interface ExploitQueueEntry {
  ID?: string;
  vulnerability_type?: string;
}

interface ExploitQueueDocument {
  vulnerabilities?: ExploitQueueEntry[];
}

async function readExploitQueue(queuePath: string): Promise<{ validIds: Set<string>; idToType: Map<string, string> }> {
  const validIds = new Set<string>();
  const idToType = new Map<string, string>();
  if (!(await fileExists(queuePath))) {
    return { validIds, idToType };
  }
  let doc: ExploitQueueDocument;
  try {
    doc = await readJson<ExploitQueueDocument>(queuePath);
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : String(error);
    const failure = ApplicationFailure.nonRetryable(
      truncateErrorMessage(`Invalid exploitation queue ${queuePath}: ${rawMessage}`),
      'InvalidExploitationQueueError',
      [{ queuePath }],
    );
    truncateStackTrace(failure);
    throw failure;
  }
  for (const entry of doc.vulnerabilities ?? []) {
    if (!entry.ID) continue;
    validIds.add(entry.ID);
    idToType.set(entry.ID, entry.vulnerability_type ?? 'unknown');
  }
  return { validIds, idToType };
}

async function runExploitAgentWithCollector(
  agentName:
    | 'injection-exploit'
    | 'xss-exploit'
    | 'auth-exploit'
    | 'ssrf-exploit'
    | 'authz-exploit'
    | 'miscellaneous-exploit',
  vulnClass: ReconciliationClass,
  input: ActivityInput,
): Promise<AgentMetrics> {
  const { createExploitCollector } = await import('../collectors/exploit-collector.js');
  const { renderExploitDeliverable } = await import('../services/exploit-renderer.js');

  const dir = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  const queuePath = path.join(dir, `${vulnClass}_exploitation_queue.json`);
  const expansion = input.exploreExpansion === true;
  const candidateQueuePath = path.join(dir, `explore_candidates_${vulnClass}.json`);
  let originalQueue: string | undefined;
  if (expansion) {
    let candidateCount = 0;
    try {
      const parsed = JSON.parse(await fs.readFile(candidateQueuePath, 'utf8')) as { vulnerabilities?: unknown };
      candidateCount = Array.isArray(parsed.vulnerabilities) ? parsed.vulnerabilities.length : 0;
    } catch {
      /* no discovered candidates for this class */
    }
    if (candidateCount === 0)
      return {
        durationMs: 0,
        inputTokens: null,
        outputTokens: null,
        cacheReadTokens: null,
        cacheWriteTokens: null,
        costUsd: 0,
        numTurns: 0,
        skipped: true,
      };
    originalQueue = await fs.readFile(queuePath, 'utf8');
    const candidates = await fs.readFile(candidateQueuePath, 'utf8');
    await atomicWrite(queuePath, candidates);
  }
  const { validIds, idToType } = await readExploitQueue(queuePath);

  const collector = createExploitCollector({ vulnClass, validIds });

  const writeDeliverable = async (deliverablesPath: string): Promise<void> => {
    const logger = createActivityLogger();
    const collected = collector.getAll();
    const emittedIds = new Set(collected.map((e) => e.vulnerability_id));
    const missingIds = [...validIds].filter((id) => !emittedIds.has(id));
    const exploitedCount = collected.filter((e) => e.status === 'exploited').length;
    const blockedCount = collected.filter((e) => e.status === 'blocked').length;

    logger.info(`${vulnClass} exploit tool call metrics`, {
      queueSize: validIds.size,
      exploited: exploitedCount,
      blocked: blockedCount,
      missing: missingIds.length,
    });

    const collectorRelPath = expansion
      ? `explore_expansion_${vulnClass}_exploit_collector.json`
      : sparseExploitCollectorPath(vulnClass);
    await atomicWrite(path.join(deliverablesPath, collectorRelPath), `${JSON.stringify(collected, null, 2)}\n`);
    logger.info(`Wrote ${collectorRelPath} with ${collected.length} collector entries`);

    const markdown = renderExploitDeliverable(vulnClass, collected, idToType);
    const mdPath = path.join(
      deliverablesPath,
      expansion ? `explore_expansion_${vulnClass}_exploitation_evidence.md` : `${vulnClass}_exploitation_evidence.md`,
    );
    await atomicWrite(mdPath, markdown);
    logger.info(
      `Wrote ${expansion ? `explore_expansion_${vulnClass}_exploitation_evidence.md` : `${vulnClass}_exploitation_evidence.md`} from structured data (${markdown.length} bytes)`,
    );
    if (expansion) {
      const expansionReportPath = path.join(deliverablesPath, `explore_expansion_${vulnClass}.md`);
      const prior = await fs
        .readFile(expansionReportPath, 'utf8')
        .catch(() => `# Template-based expansion review: ${vulnClass}\n`);
      await atomicWrite(expansionReportPath, `${prior}\n## Exploitation of additional findings\n\n${markdown}\n`);
    }
    if (originalQueue !== undefined) await atomicWrite(queuePath, originalQueue);
  };
  try {
    const extra = expansion
      ? await loadPromptFragment(
          'explore-expansion-exploit',
          input.pipelineTestingMode ?? false,
          createActivityLogger(),
          input.promptDir,
        )
      : undefined;
    const auditAgentName = expansion ? (`${vulnClass}-exploit-expansion` as PostExploitationStage) : undefined;
    return await runAgentActivity(
      agentName,
      input,
      collector.tools,
      writeDeliverable,
      'terminal',
      !expansion,
      extra,
      auditAgentName,
    );
  } finally {
    if (originalQueue !== undefined) await atomicWrite(queuePath, originalQueue);
  }
}

export async function runInjectionExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runExploitAgentWithCollector('injection-exploit', 'injection', input);
}

export async function runXssExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runExploitAgentWithCollector('xss-exploit', 'xss', input);
}

export async function runAuthExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runExploitAgentWithCollector('auth-exploit', 'auth', input);
}

export async function runSsrfExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runExploitAgentWithCollector('ssrf-exploit', 'ssrf', input);
}

export async function runAuthzExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runExploitAgentWithCollector('authz-exploit', 'authz', input);
}

/** Run the ordinary collector-backed agent after durable admission appended it to the expected set. */
export async function runMiscellaneousExploitAgent(input: ActivityInput): Promise<AgentMetrics> {
  return runExploitAgentWithCollector('miscellaneous-exploit', 'miscellaneous', input);
}

/** Replay documented exploit proof after exploration has finished; unresolved results are durable but report-excluded. */
export async function runRecordAgent(input: ActivityInput): Promise<AgentMetrics> {
  const { createRecordCollector } = await import('../collectors/record-collector.js');
  const classes: ReconciliationClass[] = ['injection', 'xss', 'auth', 'ssrf', 'authz', 'miscellaneous'];
  const dir = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  const validIds = new Set<string>();
  for (const vulnerabilityClass of classes) {
    const queueFile = path.join(
      dir,
      input.exploreExpansion
        ? `explore_candidates_${vulnerabilityClass}.json`
        : `${vulnerabilityClass}_exploitation_queue.json`,
    );
    try {
      const queue = JSON.parse(await fs.readFile(queueFile, 'utf8')) as { vulnerabilities?: Array<{ ID?: unknown }> };
      for (const vulnerability of queue.vulnerabilities ?? [])
        if (typeof vulnerability.ID === 'string') validIds.add(vulnerability.ID);
    } catch {
      // An absent class queue simply means there were no findings of that class.
    }
  }
  const container = getOrCreateContainer(input.workflowId, buildSessionMetadata(input), buildContainerConfig(input));
  const config = await container.configLoader.loadOptional(input.configPath, undefined, input.configYAML);
  if (isErr(config)) throw deterministicActivityFailure(config.error, 'ConfigurationError');
  const captureRedactions = configuredCaptureRedactions(config.value?.authentication?.credentials);
  const collector = createRecordCollector({
    deliverablesDir: dir,
    targetUrl: input.webUrl,
    sourceDir: input.repoPath,
    validIds,
    secrets: captureRedactions.map((item) => item.value),
  });
  const writeDeliverable = async (deliverablesPath: string): Promise<void> => {
    const { renderExploitDeliverable } = await import('../services/exploit-renderer.js');
    const redact = (value: string) =>
      captureRedactions.reduce((text, item) => text.split(item.value).join(item.placeholder), value);
    const verdicts = collector.getAll().map((verdict) => ({
      ...verdict,
      reason: redact(verdict.reason),
      frontend_url: verdict.frontend_url === null ? null : redact(verdict.frontend_url),
      frontend_trigger: verdict.frontend_trigger === null ? null : redact(verdict.frontend_trigger),
      frontend_reason: redact(verdict.frontend_reason),
    }));
    const byId = new Map(verdicts.map((verdict) => [verdict.finding_id, verdict]));
    const pending: typeof verdicts = [];
    const verifiedFindingIds = new Set<string>();
    for (const vulnerabilityClass of classes) {
      const sourceCollectorPath = path.join(
        deliverablesPath,
        input.exploreExpansion
          ? `explore_expansion_${vulnerabilityClass}_exploit_collector.json`
          : `${vulnerabilityClass}_exploit_collector.json`,
      );
      const renumberedCollectorPath = input.exploreExpansion
        ? sourceCollectorPath
        : path.join(deliverablesPath, `${vulnerabilityClass}_exploit_collector_renumbered.json`);
      let sourceEntries: Array<Record<string, unknown> & { vulnerability_id?: string; status?: string }>;
      try {
        sourceEntries = JSON.parse(await fs.readFile(sourceCollectorPath, 'utf8')) as Array<
          Record<string, unknown> & { vulnerability_id?: string; status?: string }
        >;
      } catch {
        continue;
      }
      for (const entry of sourceEntries) {
        if (entry.status !== 'exploited' || !entry.vulnerability_id || byId.has(entry.vulnerability_id)) continue;
        const unresolved = {
          finding_id: entry.vulnerability_id,
          status: 'manual_review' as const,
          reason: 'No replay verdict was recorded.',
          capture_ids: [],
          frontend_status: 'unable_to_determine' as const,
          frontend_url: null,
          frontend_trigger: null,
          frontend_reason: 'The record agent did not establish the frontend entry point.',
        };
        verdicts.push(unresolved);
        byId.set(entry.vulnerability_id, unresolved);
      }
      for (const entry of sourceEntries) {
        if (!entry.vulnerability_id) continue;
        const verdict = byId.get(entry.vulnerability_id);
        if (verdict?.status === 'verified') {
          entry.http_evidence_ids = verdict.capture_ids;
          entry.http_evidence_receipts = verdict.http_evidence_receipts ?? [];
          entry.http_evidence_display = 'include';
          entry.verification_method = 'http';
          entry.http_evidence_reason = verdict.reason;
        } else if (entry.status === 'exploited') {
          entry.http_evidence_ids = [];
          entry.http_evidence_receipts = [];
          entry.http_evidence_display = 'omit';
          entry.verification_method = 'other';
          entry.http_evidence_reason =
            verdict?.reason ?? 'No replay verdict was recorded; manual verification is pending.';
        }
      }
      await atomicWrite(sourceCollectorPath, `${JSON.stringify(sourceEntries, null, 2)}\n`);

      let entries = sourceEntries;
      let finalIdToSourceId = new Map<string, string>();
      try {
        entries = JSON.parse(await fs.readFile(renumberedCollectorPath, 'utf8')) as typeof sourceEntries;
        const renumberMap = JSON.parse(
          await fs.readFile(path.join(deliverablesPath, `${vulnerabilityClass}_renumber_map.json`), 'utf8'),
        ) as { map?: Record<string, string> };
        finalIdToSourceId = new Map(
          Object.entries(renumberMap.map ?? {}).map(([sourceId, finalId]) => [finalId, sourceId]),
        );
      } catch {
        /* no renumbered artifact for an empty or absent class */
      }
      for (const entry of entries) {
        if (!entry.vulnerability_id) continue;
        const sourceId = finalIdToSourceId.get(entry.vulnerability_id) ?? entry.vulnerability_id;
        const verdict = byId.get(sourceId);
        if (verdict?.status === 'verified') {
          entry.http_evidence_ids = verdict.capture_ids;
          entry.http_evidence_receipts = verdict.http_evidence_receipts ?? [];
          entry.http_evidence_display = 'include';
          entry.verification_method = 'http';
          entry.http_evidence_reason = verdict.reason;
        } else if (entry.status === 'exploited') {
          entry.http_evidence_ids = [];
          entry.http_evidence_receipts = [];
          entry.http_evidence_display = 'omit';
          entry.verification_method = 'other';
          entry.http_evidence_reason =
            verdict?.reason ?? 'No replay verdict was recorded; manual verification is pending.';
        }
      }
      if (entries !== sourceEntries)
        await atomicWrite(renumberedCollectorPath, `${JSON.stringify(entries, null, 2)}\n`);
      const filtered = entries.filter(
        (entry) =>
          entry.status !== 'exploited' ||
          (!!entry.vulnerability_id &&
            byId.get(finalIdToSourceId.get(entry.vulnerability_id) ?? entry.vulnerability_id)?.status === 'verified'),
      );
      for (const entry of filtered) {
        // A blocked exploit is still a source-confirmed finding. Replay gates only findings
        // whose exploit agent claimed a successful, replayable proof.
        if ((entry.status === 'blocked' || entry.status === 'exploited') && entry.vulnerability_id)
          verifiedFindingIds.add(entry.vulnerability_id);
      }
      const queuePath = path.join(
        deliverablesPath,
        input.exploreExpansion
          ? `explore_candidates_${vulnerabilityClass}.json`
          : `${vulnerabilityClass}_exploitation_queue.json`,
      );
      let idToType = new Map<string, string>();
      try {
        idToType = (await readExploitQueue(queuePath)).idToType;
      } catch {
        /* render with stable IDs only */
      }
      let recordedMarkdown = renderExploitDeliverable(
        vulnerabilityClass,
        filtered as import('../collectors/exploit-collector.js').AddExploitInput[],
        idToType,
      );
      const replayed = verdicts.filter(
        (verdict) =>
          filtered.some(
            (entry) =>
              (finalIdToSourceId.get(entry.vulnerability_id ?? '') ?? entry.vulnerability_id) === verdict.finding_id,
          ) && verdict.status === 'verified',
      );
      if (replayed.length) {
        recordedMarkdown += `\n\n## Record-stage replay and frontend reproduction\n\n${replayed
          .map((verdict) => {
            const frontend =
              verdict.frontend_status === 'available'
                ? `Frontend URL: ${verdict.frontend_url}\n\nFrontend trigger: ${verdict.frontend_trigger}`
                : `Frontend status: ${verdict.frontend_status} — ${verdict.frontend_reason}`;
            return `- ${verdict.finding_id}: packet captures ${verdict.capture_ids.join(', ')}; ${verdict.reason}\n\n  ${frontend}`;
          })
          .join('\n')}\n`;
      }
      await atomicWrite(
        path.join(
          deliverablesPath,
          input.exploreExpansion
            ? `explore_expansion_${vulnerabilityClass}_recorded_exploitation_evidence.md`
            : `${vulnerabilityClass}_recorded_exploitation_evidence.md`,
        ),
        recordedMarkdown,
      );
      if (input.exploreExpansion && filtered.length) {
        const expansionReportPath = path.join(deliverablesPath, `explore_expansion_${vulnerabilityClass}.md`);
        const previous = await fs.readFile(expansionReportPath, 'utf8').catch(() => '');
        await atomicWrite(
          expansionReportPath,
          `${previous}\n## Replay verification of additional findings\n\n${recordedMarkdown}\n`,
        );
      }
      for (const entry of sourceEntries) {
        if (entry.status !== 'exploited' || !entry.vulnerability_id) continue;
        const verdict = byId.get(entry.vulnerability_id);
        if (!verdict || verdict.status !== 'verified') {
          pending.push(
            verdict ?? {
              finding_id: entry.vulnerability_id,
              status: 'manual_review' as const,
              reason: 'No replay verdict was recorded.',
              capture_ids: [],
              frontend_status: 'unable_to_determine' as const,
              frontend_url: null,
              frontend_trigger: null,
              frontend_reason: 'The record agent did not establish the frontend entry point.',
            },
          );
        }
      }
    }
    let allVerdicts = verdicts;
    let allVerifiedFindingIds = verifiedFindingIds;
    if (input.exploreExpansion) {
      const previousVerdicts = JSON.parse(
        await fs.readFile(path.join(deliverablesPath, 'record_verification.json'), 'utf8'),
      ) as typeof verdicts;
      const previousIds = JSON.parse(
        await fs.readFile(path.join(deliverablesPath, 'record_verified_finding_ids.json'), 'utf8'),
      ) as string[];
      allVerdicts = [...previousVerdicts, ...verdicts];
      allVerifiedFindingIds = new Set([...previousIds, ...verifiedFindingIds]);
    }
    await atomicWrite(
      path.join(deliverablesPath, 'record_verification.json'),
      `${JSON.stringify(allVerdicts, null, 2)}\n`,
    );
    await atomicWrite(
      path.join(deliverablesPath, 'record_verified_finding_ids.json'),
      `${JSON.stringify([...allVerifiedFindingIds].sort(), null, 2)}\n`,
    );
    const lines = [
      '# Record and Replay Results',
      '',
      ...allVerdicts.flatMap((v) => [
        `- **${v.finding_id} — ${v.status}**: ${v.reason}`,
        v.frontend_status === 'available'
          ? `  Frontend: ${v.frontend_url} — ${v.frontend_trigger}`
          : `  Frontend: ${v.frontend_status} — ${v.frontend_reason}`,
      ]),
    ];
    await atomicWrite(path.join(deliverablesPath, 'record_verification.md'), `${lines.join('\n')}\n`);
    const pendingLines = [
      '# Pending Manual Verification',
      '',
      'The following exploitation findings could not be replay-verified and are omitted from the final report.',
      '',
    ];
    for (const item of pending) {
      pendingLines.push(`- **${item.finding_id}**: ${item.reason}`);
      pendingLines.push(
        item.frontend_status === 'available'
          ? `  Frontend: ${item.frontend_url} — ${item.frontend_trigger}`
          : `  Frontend: ${item.frontend_status} — ${item.frontend_reason}`,
      );
    }
    if (!pending.length) pendingLines.push('No findings are pending manual verification.');
    if (input.exploreExpansion) {
      const originalPending = await fs
        .readFile(path.join(deliverablesPath, 'pending_manual_verification.md'), 'utf8')
        .catch(() => '');
      if (originalPending)
        pendingLines.splice(0, 3, originalPending.trimEnd(), '', '## Expansion findings pending replay');
    }
    await atomicWrite(path.join(deliverablesPath, 'pending_manual_verification.md'), `${pendingLines.join('\n')}\n`);
  };
  const expansionInstructions = input.exploreExpansion
    ? await loadPromptFragment(
        'explore-expansion-record',
        input.pipelineTestingMode ?? false,
        createActivityLogger(),
        input.promptDir,
      )
    : undefined;
  return runAgentActivity(
    'record',
    input,
    collector.tools,
    writeDeliverable,
    'terminal',
    true,
    expansionInstructions,
    input.exploreExpansion ? 'record-expansion' : undefined,
  );
}

/** Extract sink templates with an agent, then search the assessed source tree with deterministic ripgrep. */
export async function runExploreAgent(input: ActivityInput): Promise<AgentMetrics> {
  const { createExploreCollector } = await import('../collectors/explore-collector.js');
  const { searchExploreTemplates } = await import('../services/explore-search.js');
  const classes: ReconciliationClass[] = ['injection', 'xss', 'auth', 'ssrf', 'authz', 'miscellaneous'];
  const dir = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  const verifiedIdsRaw = JSON.parse(
    await fs.readFile(path.join(dir, 'record_verified_finding_ids.json'), 'utf8'),
  ) as unknown;
  if (!Array.isArray(verifiedIdsRaw) || verifiedIdsRaw.some((id) => typeof id !== 'string'))
    throw ApplicationFailure.nonRetryable(
      'Record verification IDs are invalid; Explore cannot establish trusted sinks.',
      'RecordVerificationError',
    );
  const verifiedIds = new Set(verifiedIdsRaw as string[]);
  const sinks = new Map<string, { vulnerabilityClass: string; locations: Map<string, Set<number>> }>();
  for (const vulnerabilityClass of classes) {
    const collectorPath = path.join(dir, `${vulnerabilityClass}_exploit_collector_renumbered.json`);
    let entries: Array<{ vulnerability_id?: unknown; status?: unknown; code_locations?: unknown }>;
    try {
      entries = JSON.parse(await fs.readFile(collectorPath, 'utf8')) as typeof entries;
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (
        entry.status !== 'exploited' ||
        typeof entry.vulnerability_id !== 'string' ||
        !verifiedIds.has(entry.vulnerability_id)
      )
        continue;
      const locations = new Map<string, Set<number>>();
      for (const location of Array.isArray(entry.code_locations) ? entry.code_locations : []) {
        if (!location || typeof location !== 'object') continue;
        const row = location as { workspace_relative_file_path?: unknown; line_number?: unknown };
        if (typeof row.workspace_relative_file_path !== 'string' || typeof row.line_number !== 'number') continue;
        const lineSet = locations.get(row.workspace_relative_file_path) ?? new Set<number>();
        lineSet.add(row.line_number);
        locations.set(row.workspace_relative_file_path, lineSet);
      }
      if (locations.size) sinks.set(entry.vulnerability_id, { vulnerabilityClass, locations });
    }
  }
  const collector = createExploreCollector({ sinks });
  const writeDeliverable = async (deliverablesPath: string): Promise<void> => {
    const templates = collector.getAll();
    const search = await searchExploreTemplates(input.repoPath, templates);
    await atomicWrite(path.join(deliverablesPath, 'explore_templates.json'), `${JSON.stringify(templates, null, 2)}\n`);
    await atomicWrite(
      path.join(deliverablesPath, 'explore_search_results.json'),
      `${JSON.stringify(search, null, 2)}\n`,
    );
    const lines = [
      '# Template-based Source Exploration',
      '',
      'Templates are model-derived from record-verified sink locations. All repository search results below were generated deterministically by ripgrep.',
      '',
    ];
    for (const template of templates)
      lines.push(
        `- ${template.finding_id} (${template.vulnerability_class}) — ${template.sink_file}:${template.sink_line} — \`${template.regex}\` — ${template.rationale}`,
      );
    lines.push('', '## Matching Source Locations', '');
    for (const match of search.matches)
      lines.push(
        `- ${match.finding_id}: ${match.match_file}:${match.match_line} — \`${match.excerpt.replace(/`/g, '\\`')}\``,
      );
    if (!search.matches.length) lines.push('No additional source locations matched the submitted templates.');
    if (search.truncated) lines.push('', 'Search results were truncated; additional matches may exist.');
    if (search.rejected.length) {
      lines.push('', '## Rejected Templates', '');
      for (const item of search.rejected) lines.push(`- ${item.template.finding_id}: ${item.reason}`);
    }
    await atomicWrite(path.join(deliverablesPath, 'explore_deliverable.md'), `${lines.join('\n')}\n`);
  };
  return runAgentActivity('explore', input, collector.tools, writeDeliverable);
}

/** Execute one report-preparation stage behind the durable post-exploitation checkpoint. */
export async function runPostExploitationStage(
  input: ActivityInput,
  stage: PostExploitationStage,
): Promise<AgentMetrics> {
  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  const dir = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  const run = async (): Promise<AgentMetrics> => {
    switch (stage) {
      case 'record':
        return runRecordAgent(input);
      case 'explore':
        return runExploreAgent(input);
      case 'injection-vuln-expansion':
        return runInjectionVulnExpansionAgent(input);
      case 'xss-vuln-expansion':
        return runXssVulnExpansionAgent(input);
      case 'auth-vuln-expansion':
        return runAuthVulnExpansionAgent(input);
      case 'authz-vuln-expansion':
        return runAuthzVulnExpansionAgent(input);
      case 'ssrf-vuln-expansion':
        return runSsrfVulnExpansionAgent(input);
      case 'injection-exploit-expansion':
        return runInjectionExploitAgent({ ...input, exploreExpansion: true });
      case 'xss-exploit-expansion':
        return runXssExploitAgent({ ...input, exploreExpansion: true });
      case 'auth-exploit-expansion':
        return runAuthExploitAgent({ ...input, exploreExpansion: true });
      case 'authz-exploit-expansion':
        return runAuthzExploitAgent({ ...input, exploreExpansion: true });
      case 'ssrf-exploit-expansion':
        return runSsrfExploitAgent({ ...input, exploreExpansion: true });
      case 'record-expansion':
        return runRecordAgent({ ...input, exploreExpansion: true });
    }
    const exhaustiveStage: never = stage;
    void exhaustiveStage;
    throw new RunStateError('CorruptedSessionError', 'post-exploitation-stage-invalid');
  };
  try {
    return await runPostExploitationPass(auditSession, dir, stage, createActivityLogger(), run);
  } catch (error) {
    if (error instanceof PostExploitationReplayRequiredError) {
      throw ApplicationFailure.nonRetryable(
        'A target-affecting post-exploitation step was interrupted without a durable completion record. Review the target before resuming this workspace.',
        'PostExploitationReplayRequiredError',
        [{ stage: error.stage }],
      );
    }
    if (error instanceof RunStateError) throw runStateFailure(error);
    throw error;
  }
}

export async function runReportAgent(input: ActivityInput, exploit: boolean): Promise<AgentMetrics> {
  const { createFindingCollector } = await import('../collectors/finding-collector.js');
  const assessmentDate = input.assessmentDate;
  if (assessmentDate === undefined) {
    throw ApplicationFailure.nonRetryable('The report assessment date is missing.', 'ConfigurationError', [
      { checkCode: 'report-assessment-date-missing' },
    ]);
  }

  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  let durableState = await auditSession.getDurableScanState();
  if (durableState.exploit !== exploit) {
    throw runStateFailure(new RunStateError('IncompatibleWorkspaceError', 'report-exploit-mode-mismatch'));
  }
  if (durableState.report === undefined) {
    throw runStateFailure(new RunStateError('DurableStateConflictError', 'report-progress-not-initialized'));
  }
  let reportProgress = durableState.report;
  const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  if (reportProgress.stage === 'draft') {
    const validation = await validateDraftProgress(deliverablesPath, reportProgress);
    if (validation === 'invalid-model') {
      await rollbackInvalidReportDraft(input, reportProgress);
      durableState = await auditSession.getDurableScanState();
      if (durableState.report?.stage !== 'pending') {
        throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-draft-rollback-did-not-persist'));
      }
      reportProgress = durableState.report;
    } else if (validation === 'invalid-canonical') {
      throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-canonical-checkpoint-invalid'));
    }
  }
  if (reportProgress.stage === 'finalized' && !(await finalProgressIsCoherent(deliverablesPath, reportProgress))) {
    throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-final-proof-invalid'));
  }
  if (reportProgress.stage !== 'pending') {
    return { ...(await auditSession.getReportMetrics()), skipped: true };
  }

  let verifiedFindingIds: ReadonlySet<string> | undefined;
  if (exploit) {
    try {
      const ids = JSON.parse(
        await fs.readFile(path.join(deliverablesPath, 'record_verified_finding_ids.json'), 'utf8'),
      ) as unknown;
      if (!Array.isArray(ids) || ids.some((id) => typeof id !== 'string')) throw new Error('invalid finding allowlist');
      verifiedFindingIds = new Set(ids as string[]);
    } catch {
      throw ApplicationFailure.nonRetryable(
        'Record-stage verification results are missing or invalid; the report cannot include unverified findings.',
        'RecordVerificationError',
      );
    }
  }
  const collector = createFindingCollector(exploit, verifiedFindingIds);
  const evidenceContainer = getOrCreateContainer(
    input.workflowId,
    buildSessionMetadata(input),
    buildContainerConfig(input),
  );
  const evidenceConfig = await evidenceContainer.configLoader.loadOptional(
    input.configPath,
    undefined,
    input.configYAML,
  );
  if (isErr(evidenceConfig)) throw deterministicActivityFailure(evidenceConfig.error, 'ConfigurationError');
  const captureRedactions = configuredCaptureRedactions(evidenceConfig.value?.authentication?.credentials);

  const writeDeliverable = async (deliverablesPath: string, execution: { readonly model?: string }): Promise<void> => {
    const logger = createActivityLogger();
    const { attachQueueCodeLocations } = await import('../services/code-location-join.js');
    const collected = collector.getAll();
    logger.info(`Collected ${collected.length} finding(s) from report agent`);
    const findingsWithLocations = await attachQueueCodeLocations(
      collected,
      deliverablesPath,
      logger,
      durableState.participating_classes,
    );
    const findings = exploit
      ? await attachHttpEvidence(findingsWithLocations, deliverablesPath, captureRedactions)
      : findingsWithLocations;

    // report_meta is written by the set-report-meta CLI while the agent runs; read it back so
    // the two halves of report.json end up in one document.
    const reportJsonPath = path.join(deliverablesPath, REPORT_JSON_FILENAME);
    let reportMeta: ReportMeta = {
      target: input.webUrl,
      assessment_date: assessmentDate,
      scope: '',
      executive_summary: '',
      exploit,
    };
    if (await fileExists(reportJsonPath)) {
      try {
        const existing = await readJson<{ report_meta?: Record<string, unknown> }>(reportJsonPath);
        if (existing.report_meta) {
          reportMeta = {
            target: String(existing.report_meta.target ?? input.webUrl),
            assessment_date: String(existing.report_meta.assessment_date ?? reportMeta.assessment_date),
            scope: String(existing.report_meta.scope ?? ''),
            executive_summary: String(existing.report_meta.executive_summary ?? ''),
            exploit,
            ...(execution.model !== undefined && { model: execution.model }),
          };
        }
      } catch {
        logger.warn('Failed to read report_meta from report.json, using defaults');
      }
    }
    if (execution.model !== undefined) {
      reportMeta = { ...reportMeta, model: execution.model };
    } else {
      logger.warn('Report execution returned no model identifier; canonical report metadata omits model');
    }
    reportMeta = {
      ...reportMeta,
      // The workflow supplies the scan date to the prompt and owns the final field. A model-written
      // value cannot move the assessment to a different day.
      assessment_date: assessmentDate,
      // The workflow owns the assessed class set. The model may summarize the engagement,
      // but it cannot rename or omit the canonical scope in customer output.
      scope: formatVulnClassScope(resolveAnalysisClasses(input)),
    };

    const reportData: ReportData = {
      report_meta: reportMeta,
      findings,
      ...(input.failedClasses && input.failedClasses.length > 0 && { not_assessed: input.failedClasses }),
      reconciliation_failed: [...reportProgress.renumber_failed_classes],
    };

    await atomicWrite(reportJsonPath, `${JSON.stringify(reportData, null, 2)}\n`);
    logger.info(`Wrote ${REPORT_JSON_FILENAME} with ${findings.length} finding(s)`);
  };

  return runAgentActivity('report', input, collector.tools, writeDeliverable, 'report-draft', false);
}

/**
 * Preflight validation activity.
 *
 * Runs cheap checks before any agent execution:
 * 1. Repository path exists and is a directory
 * 2. Config file validates (if provided)
 * 3. Credential validation (API key, OAuth, or Bedrock)
 * 4. Target URL reachable from the container
 *
 * NOT using runAgentActivity — preflight doesn't run a full analysis agent.
 */
export async function runPreflightValidation(input: ActivityInput): Promise<void> {
  const startTime = Date.now();
  const attemptNumber = Context.current().info.attempt;

  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ phase: 'preflight', elapsedSeconds: elapsed, attempt: attemptNumber });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const logger = createActivityLogger();
    logger.info('Running preflight validation...', { attempt: attemptNumber });

    const result = await runPreflightChecks(input.webUrl, input.repoPath, input.configPath, logger);

    if (isErr(result)) {
      const classified = classifyErrorForTemporal(result.error);
      const message = truncateErrorMessage(result.error.message);

      if (classified.retryable) {
        const failure = ApplicationFailure.create({
          message,
          type: classified.type,
          details: [{ phase: 'preflight', attemptNumber, elapsed: Date.now() - startTime }],
        });
        truncateStackTrace(failure);
        throw failure;
      } else {
        const failure = ApplicationFailure.nonRetryable(message, classified.type, [
          { phase: 'preflight', attemptNumber, elapsed: Date.now() - startTime },
        ]);
        truncateStackTrace(failure);
        throw failure;
      }
    }

    logger.info('Preflight validation passed');
  } catch (error) {
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    const classified = classifyErrorForTemporal(error);
    const rawMessage = error instanceof Error ? error.message : String(error);
    const message = truncateErrorMessage(rawMessage);

    const failure = ApplicationFailure.nonRetryable(message, classified.type, [
      { phase: 'preflight', attemptNumber, elapsed: Date.now() - startTime },
    ]);
    truncateStackTrace(failure);
    throw failure;
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/**
 * Authentication validation activity. No-ops without an authentication
 * block; otherwise surfaces a classified failure (failurePoint +
 * failureDetail in ApplicationFailure.details) on credential rejection.
 */
export async function runAuthenticationValidation(input: ActivityInput): Promise<AgentMetrics | null> {
  const startTime = Date.now();
  const attemptNumber = Context.current().info.attempt;

  const heartbeatInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    heartbeat({ phase: 'auth-validation', elapsedSeconds: elapsed, attempt: attemptNumber });
  }, HEARTBEAT_INTERVAL_MS);

  try {
    const logger = createActivityLogger();

    const sessionMetadata = buildSessionMetadata(input);
    const container = getOrCreateContainer(input.workflowId, sessionMetadata, buildContainerConfig(input));
    const configResult = await container.configLoader.loadOptional(input.configPath, undefined, input.configYAML);
    if (isErr(configResult)) {
      // runPreflightValidation already validated parsing, so this is unexpected.
      logger.warn(`runAuthenticationValidation: config load failed unexpectedly: ${configResult.error.message}`);
      return null;
    }

    const distributedConfig = configResult.value;
    if (!distributedConfig?.authentication) {
      logger.info('No authentication configured — skipping credential validation');
      return null;
    }

    const auditSession = new AuditSession(sessionMetadata);
    await auditSession.initialize(input.workflowId);

    const result = await validateAuthentication({
      distributedConfig,
      repoPath: input.repoPath,
      webUrl: input.webUrl,
      logger,
      auditSession,
      attemptNumber,
      ...(input.deliverablesSubdir !== undefined && { deliverablesSubdir: input.deliverablesSubdir }),
      ...(input.promptDir !== undefined && { promptDir: input.promptDir }),
      ...(input.pipelineTestingMode !== undefined && { pipelineTestingMode: input.pipelineTestingMode }),
      cancellationSignal: Context.current().cancellationSignal,
    });

    if (isErr(result)) {
      const classified = classifyErrorForTemporal(result.error);
      const message = truncateErrorMessage(result.error.message);
      const ctx = result.error.context;
      const details = [
        {
          phase: 'auth-validation',
          attemptNumber,
          elapsed: Date.now() - startTime,
          ...(ctx.failurePoint !== undefined && { failurePoint: ctx.failurePoint }),
          ...(ctx.failureDetail !== undefined && { failureDetail: ctx.failureDetail }),
        },
      ];

      const failure = classified.retryable
        ? ApplicationFailure.create({ message, type: classified.type, details })
        : ApplicationFailure.nonRetryable(message, classified.type, details);
      truncateStackTrace(failure);
      throw failure;
    }

    return result.value;
  } catch (error) {
    if (error instanceof ApplicationFailure) {
      throw error;
    }

    const classified = classifyErrorForTemporal(error);
    const rawMessage = error instanceof Error ? error.message : String(error);
    const message = truncateErrorMessage(rawMessage);
    const details = [{ phase: 'auth-validation', attemptNumber, elapsed: Date.now() - startTime }];

    const failure = classified.retryable
      ? ApplicationFailure.create({ message, type: classified.type, details })
      : ApplicationFailure.nonRetryable(message, classified.type, details);
    truncateStackTrace(failure);
    throw failure;
  } finally {
    clearInterval(heartbeatInterval);
  }
}

/**
 * Initialize a private git repository inside the workspace deliverables directory.
 * Idempotent — skips if .git already exists (resume case).
 */
export async function initDeliverableGit(input: ActivityInput): Promise<void> {
  const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  await fs.mkdir(deliverablesPath, { recursive: true });

  // Check for .git directly inside deliverables, not parent repo's .git
  const dotGitPath = path.join(deliverablesPath, '.git');
  try {
    await fs.stat(dotGitPath);
    return;
  } catch {
    // .git doesn't exist, proceed with init
  }

  await executeGitCommandWithRetry(['git', 'init'], deliverablesPath, 'init deliverables repo');
  await executeGitCommandWithRetry(
    ['git', 'commit', '--allow-empty', '-m', '📍 Initial deliverables checkpoint'],
    deliverablesPath,
    'initial checkpoint',
  );
}

/**
 * Drop a stealth cli.config.json into the repo's .playwright/ directory so
 * `playwright-cli open` auto-loads anti-detection defaults from the agent's
 * cwd (disables the Blink AutomationControlled flag, drops the
 * --enable-automation default, and overrides the HeadlessChrome user agent).
 *
 * No-op when the repo already has its own .playwright/cli.config.json.
 */
export async function syncPlaywrightStealthConfig(input: ActivityInput): Promise<void> {
  const logger = createActivityLogger();
  const { result, configPath } = await writePlaywrightStealthConfig(input.repoPath);
  if (result === 'skipped-existing') {
    logger.info(`Playwright stealth config: leaving existing ${configPath} in place`);
  } else {
    logger.info(`Playwright stealth config: wrote ${configPath}`);
  }
}

/**
 * Sync code_path avoid rules into the @gotgenes/pi-permission-system global config
 * so pi enforces them at the tool layer for every agent in this run. The executor
 * loads the extension when this config is present (see pi-executor).
 *
 * Runs once per workflow before any analysis agent fires. Config is fixed for the
 * lifetime of the workflow, so writing once avoids a parallel-agent race on the
 * global config file.
 */
export async function syncCodePathDenyRules(input: ActivityInput): Promise<void> {
  const logger = createActivityLogger();
  const container = getOrCreateContainer(input.workflowId, buildSessionMetadata(input), buildContainerConfig(input));

  const configResult = await container.configLoader.loadOptional(input.configPath, undefined, input.configYAML);
  if (isErr(configResult)) {
    logger.warn(`syncCodePathDenyRules: skipping (config load failed: ${configResult.error.message})`);
    return;
  }

  const config = configResult.value;
  const denyCount = (config?.avoid ?? []).filter((r) => r.type === 'code_path').length;
  syncPermissionSystemConfig(config);
  logger.info(
    denyCount > 0
      ? `Synced ${denyCount} code_path deny rule(s) to the pi-permission-system config`
      : 'No code_path deny rules; pi-permission-system config cleared',
  );
}

/** Initialize fresh state exactly once, or validate the persisted resume contract. */
export async function initializeDurableScanState(
  input: ActivityInput,
  exploit: boolean,
  context: 'fresh' | 'resume',
): Promise<DurableStateSummary> {
  try {
    const auditSession = new AuditSession(buildSessionMetadata(input));
    await auditSession.initializeDurableScanState(input.workflowId, exploit, context);
    return durableStateSummary(await auditSession.getDurableScanState());
  } catch (error) {
    throw runStateFailure(error);
  }
}

/** Persist the `miscellaneous` queue decision before any conditional agent is scheduled. */
export async function persistMiscellaneousOutcome(
  input: ActivityInput,
  outcome: MiscellaneousOutcome,
): Promise<DurableStateSummary> {
  try {
    const auditSession = new AuditSession(buildSessionMetadata(input));
    await auditSession.initialize(input.workflowId);
    return durableStateSummary(await auditSession.updateMiscellaneousOutcome(outcome));
  } catch (error) {
    throw runStateFailure(error);
  }
}

// === Report progress state machine ===
// The activities below read and advance one durable ReportProgress record through
// pending -> draft -> finalized. Every transition is verified against the actual git
// checkpoint before it is trusted (checkpointIsAncestor, reportCheckpointIsCoherent,
// finalProgressIsCoherent), so a crash between "committed the work" and "recorded the state"
// is repaired on the next attempt instead of silently accepted or silently lost.

/** Persist the ordered reconciliation-failure set and durable partial reasons before assembly. */
export async function initializeReportProgress(
  input: ActivityInput,
  failedClasses: readonly ReconciliationClass[],
  partialReasons: readonly PartialReason[],
): Promise<ReportProgress> {
  try {
    const auditSession = new AuditSession(buildSessionMetadata(input));
    await auditSession.initialize(input.workflowId);
    return await auditSession.initializeReportProgress(failedClasses, partialReasons);
  } catch (error) {
    throw runStateFailure(error);
  }
}

/** Invoke the class-local exact-output renumber service with a history-safe receipt. */
export async function renumberClassFindings(
  input: ActivityInput,
  vulnerabilityClass: ReconciliationClass,
): Promise<ReconciliationActivityResult> {
  try {
    const result = await renumberClassFindingsService({
      deliverablesDir: deliverablesDir(input.repoPath, input.deliverablesSubdir),
      vulnerabilityClass,
      logger: createActivityLogger(),
    });
    return {
      vulnerabilityClass,
      skipped: result.skipped,
      changedPathCount: result.commit?.changedPaths.length ?? 0,
      ...(result.commit !== undefined && {
        checkpoint: result.commit.commitHash,
        alreadyCommitted: result.commit.alreadyCommitted,
      }),
    };
  } catch (error) {
    throw deterministicActivityFailure(error, 'ReportRenumberError');
  }
}

/**
 * Assemble the final report by concatenating per-class deliverables.
 *
 * Under exploit=true, each exploit agent writes sparse evidence and a successful
 * renumber replaces it with the dense render. Under exploit=false, exploit agents
 * didn't run; we deterministically render `*_findings.md` from each
 * `*_exploitation_queue.json` first, then assemble.
 */
export async function assembleReportActivity(
  input: ActivityInput,
  exploit: boolean,
): Promise<AssembleReportActivityResult> {
  const { repoPath, deliverablesSubdir } = input;
  const logger = createActivityLogger();
  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  const durableState = await auditSession.getDurableScanState();
  if (durableState.exploit !== exploit || durableState.report?.stage !== 'pending') {
    throw runStateFailure(new RunStateError('DurableStateConflictError', 'report-assembly-stage-mismatch'));
  }

  let renderFailedClasses: readonly ReconciliationClass[] = [];
  if (!exploit) {
    logger.info('Rendering per-class findings from analysis queues...');
    try {
      const rendered = await renderFindingsFromQueues(
        repoPath,
        deliverablesSubdir,
        logger,
        durableState.participating_classes,
      );
      renderFailedClasses = rendered.failedClasses;
    } catch (error) {
      throw deterministicActivityFailure(error, 'ReportAssemblyError');
    }
  }

  logger.info('Assembling deliverables from specialist agents...');
  try {
    const assembled = await assembleFinalReportWithEvidence(repoPath, deliverablesSubdir, logger, {
      exploit,
      participatingClasses: durableState.participating_classes,
      knownFailedClasses: renderFailedClasses,
    });
    return { failedClasses: assembled.failedClasses };
  } catch (error) {
    throw deterministicActivityFailure(error, 'ReportAssemblyError');
  }
}

/** Compact a coherent draft using only persisted membership and failure order. */
export async function compactReportFindings(input: ActivityInput): Promise<ReconciliationActivityResult> {
  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  const state = await auditSession.getDurableScanState();
  if (state.report?.stage !== 'draft') {
    throw runStateFailure(new RunStateError('DurableStateConflictError', 'report-compaction-stage-mismatch'));
  }
  const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  const draftValidation = await validateDraftProgress(deliverablesPath, state.report);
  if (draftValidation === 'invalid-model') {
    await rollbackInvalidReportDraft(input, state.report);
    throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-draft-rolled-back'));
  }
  if (draftValidation === 'invalid-canonical') {
    throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-canonical-checkpoint-invalid'));
  }

  let result: Awaited<ReturnType<typeof compactReportFindingsService>>;
  try {
    result = await compactReportFindingsService({
      deliverablesDir: deliverablesPath,
      participatingClasses: state.participating_classes,
      renumberFailedClasses: state.report.renumber_failed_classes,
      logger: createActivityLogger(),
    });
  } catch (error) {
    throw deterministicActivityFailure(error, 'ReportCompactionError');
  }
  return {
    skipped: result.skipped,
    changedPathCount: result.commit?.changedPaths.length ?? 0,
    ...(result.commit !== undefined && {
      checkpoint: result.commit.commitHash,
      alreadyCommitted: result.commit.alreadyCommitted,
    }),
  };
}

/** Persist and validate the canonical structured checkpoint after compaction. */
export async function persistCanonicalReportProgress(
  input: ActivityInput,
  checkpoint: string,
  appendReasons: readonly PartialReason[] = [],
): Promise<ReportProgress> {
  try {
    const auditSession = new AuditSession(buildSessionMetadata(input));
    await auditSession.initialize(input.workflowId);
    const state = await auditSession.getDurableScanState();
    if (state.report?.stage !== 'draft') {
      throw new RunStateError('DurableStateConflictError', 'report-canonical-stage-mismatch');
    }
    const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
    if (
      !(await checkpointIsAncestor(state.report.model_checkpoint, checkpoint, deliverablesPath)) ||
      !(await reportCheckpointIsCoherent(deliverablesPath, checkpoint, state.report.renumber_failed_classes))
    ) {
      throw new RunStateError('CorruptedSessionError', 'report-canonical-checkpoint-invalid');
    }
    return await auditSession.recordCanonicalReportCheckpoint(checkpoint, appendReasons);
  } catch (error) {
    throw runStateFailure(error);
  }
}

/**
 * Commit exact canonical outputs and regenerate the derived PDF without terminal promotion.
 *
 * `degradedSarif` is passed by the workflow only after the retryable `ReportSarifRenderError`
 * type has exhausted the ordinary three-attempt policy; the service still runs its adoption
 * check first, so a coherent earlier commit is adopted instead of degraded.
 */
export async function finalizeReportOutputs(
  input: ActivityInput,
  degradedSarif = false,
): Promise<FinalizeReportActivityResult> {
  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  const state = await auditSession.getDurableScanState();
  if (
    state.report === undefined ||
    state.report.stage === 'pending' ||
    (state.report.stage === 'draft' && state.report.canonical_checkpoint === undefined)
  ) {
    throw runStateFailure(new RunStateError('DurableStateConflictError', 'report-finalization-stage-mismatch'));
  }

  const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  const reportIsCoherent =
    state.report.stage === 'finalized'
      ? await finalProgressIsCoherent(deliverablesPath, state.report)
      : await draftProgressIsCoherent(deliverablesPath, state.report);
  if (!reportIsCoherent) {
    throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-finalization-checkpoint-invalid'));
  }
  const priorPdfProvenance = state.report.stage === 'finalized' ? state.report.pdf_provenance : undefined;

  const container = getOrCreateContainer(input.workflowId, buildSessionMetadata(input), buildContainerConfig(input));
  const configResult = await container.configLoader.loadOptional(input.configPath, undefined, input.configYAML);
  if (isErr(configResult)) throw deterministicActivityFailure(configResult.error, 'ReportFinalizationError');
  // A run with no config file at all still leaves `report.sarif` omitted, which means on: the
  // default must match `distributeConfig`, or the commonest launch path would silently opt out.
  const reportConfig = configResult.value?.report ?? { sarif: true };
  let result: Awaited<ReturnType<typeof finalizeReport>>;
  try {
    result = await finalizeReport({
      deliverablesDir: deliverablesPath,
      exploit: state.exploit,
      partialReasons: state.report.partial_reasons,
      reconciliationFailedClasses: state.report.renumber_failed_classes,
      reportConfig,
      workspaceName: input.sessionId,
      logger: createActivityLogger(),
      templatePath: TYPST_TEMPLATE,
      ...(degradedSarif && { degradedSarif }),
      ...(priorPdfProvenance !== undefined && { priorPdfProvenance }),
    });
  } catch (error) {
    throw deterministicActivityFailure(error, 'ReportFinalizationError');
  }
  const manifestContents = `${JSON.stringify(result.manifest, null, 2)}\n`;
  return {
    checkpoint: result.commit.commitHash,
    manifestSha256: sha256(manifestContents),
    changedPathCount: result.commit.changedPaths.length,
    alreadyCommitted: result.commit.alreadyCommitted,
    sarifDisposition: result.manifest.artifacts.sarif.disposition,
    pdfGenerated: result.pdfGenerated,
    pdfProvenance: result.pdfProvenance,
    warningCount: result.warnings.length,
  };
}

export interface FinalizedReportPersistence {
  readonly sarifDisposition: ReportSarifDisposition;
  readonly pdfProvenance: StoredPdfProvenance | null;
  readonly partialReasons: readonly PartialReason[];
}

/**
 * Verify exact final bytes, then atomically promote report to the only terminal state.
 * `final_checkpoint` and the manifest digest are strict match-or-conflict fields; the PDF
 * provenance is replaceable, and partial reasons are append-only.
 */
export async function persistFinalizedReportProgress(
  input: ActivityInput,
  checkpoint: string,
  manifestSha256: string,
  terminal: FinalizedReportPersistence,
): Promise<ReportProgress> {
  try {
    if (!isOrderedPartialReasonSet(terminal.partialReasons)) {
      throw new RunStateError('DurableStateConflictError', 'report-terminal-reasons-invalid');
    }
    const auditSession = new AuditSession(buildSessionMetadata(input));
    await auditSession.initialize(input.workflowId);
    const state = await auditSession.getDurableScanState();
    if (state.report?.stage === 'finalized') {
      if (
        state.report.final_checkpoint !== checkpoint ||
        state.report.finalization_manifest_sha256 !== manifestSha256
      ) {
        throw new RunStateError('DurableStateConflictError', 'report-finalized-retry-conflict');
      }
      if (!(await finalProgressIsCoherent(deliverablesDir(input.repoPath, input.deliverablesSubdir), state.report))) {
        throw new RunStateError('CorruptedSessionError', 'report-finalized-proof-corrupt');
      }
      return await auditSession.finalizeReportProgress(checkpoint, manifestSha256, terminal);
    }
    if (state.report?.stage !== 'draft' || state.report.canonical_checkpoint === undefined) {
      throw new RunStateError('DurableStateConflictError', 'report-terminal-stage-mismatch');
    }
    const candidate: ReportProgress = {
      stage: 'finalized',
      renumber_failed_classes: [...state.report.renumber_failed_classes],
      partial_reasons: appendPartialReasons(state.report.partial_reasons, terminal.partialReasons),
      model_checkpoint: state.report.model_checkpoint,
      canonical_checkpoint: state.report.canonical_checkpoint,
      final_checkpoint: checkpoint,
      finalization_manifest_sha256: manifestSha256,
      sarif_disposition: terminal.sarifDisposition,
      ...(terminal.pdfProvenance !== null && { pdf_provenance: terminal.pdfProvenance }),
    };
    if (!(await finalProgressIsCoherent(deliverablesDir(input.repoPath, input.deliverablesSubdir), candidate))) {
      throw new RunStateError('CorruptedSessionError', 'report-final-proof-invalid');
    }
    return await auditSession.finalizeReportProgress(checkpoint, manifestSha256, terminal);
  } catch (error) {
    throw runStateFailure(error);
  }
}

/** Best-effort customer publication after durable terminal promotion. */
export async function surfaceReportOutputs(input: ActivityInput): Promise<SurfaceReportActivityResult> {
  const auditSession = new AuditSession(buildSessionMetadata(input));
  await auditSession.initialize(input.workflowId);
  const state = await auditSession.getDurableScanState();
  const deliverablesPath = deliverablesDir(input.repoPath, input.deliverablesSubdir);
  if (state.report?.stage !== 'finalized' || !(await finalProgressIsCoherent(deliverablesPath, state.report))) {
    throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-surface-terminal-proof-invalid'));
  }

  if (state.exploit) {
    // Also repair scripts for older, already-finalized runs that resume directly at publication.
    // New finalizations generate the script in finalizeReport, including report-only recovery.
    const reportData = JSON.parse(
      await fs.readFile(path.join(deliverablesPath, REPORT_JSON_FILENAME), 'utf8'),
    ) as ReportData;
    const scriptPath = await writeReproductionScript(
      deliverablesPath,
      input.webUrl,
      new Set(reportData.findings.map((finding) => finding.finding_id)),
    );
    createActivityLogger().info(`Wrote ${path.basename(scriptPath)} from final report findings`);
  }

  // The manifest just proved coherent, so the canonical digest read cannot miss here.
  const manifestContents = await checkpointFileContents(
    deliverablesPath,
    state.report.final_checkpoint,
    REPORT_FINALIZATION_MANIFEST_FILENAME,
  );
  if (manifestContents === null) {
    throw runStateFailure(new RunStateError('CorruptedSessionError', 'report-surface-terminal-proof-invalid'));
  }
  const manifest = JSON.parse(manifestContents) as { artifacts: { report_json: { sha256: string } } };
  const canonicalReportSha256 = manifest.artifacts.report_json.sha256;

  // Only provenance that matches the current renderer, template, and PDF bytes is passed
  // through; anything else surfaces as null so stale customer output is removed.
  let verifiedProvenance: StoredPdfProvenance | null = null;
  const storedProvenance = state.report.pdf_provenance;
  if (
    storedProvenance !== undefined &&
    (await pdfProvenanceIsCurrent({
      pdfPath: path.join(deliverablesPath, ASSEMBLED_REPORT_PDF_FILENAME),
      canonicalReportSha256,
      provenance: storedProvenance,
      templatePath: TYPST_TEMPLATE,
    }))
  ) {
    verifiedProvenance = storedProvenance;
  }

  const customerDir =
    input.customerOutputRoute === 'mounted'
      ? '/app/output'
      : generateAuditPath({ id: input.sessionId, webUrl: input.webUrl, repoPath: input.repoPath });
  const result = await surfaceReportOutputsService({
    deliverablesDir: deliverablesPath,
    customerDir,
    logger: createActivityLogger(),
    pdfVerification: { canonicalReportSha256, provenance: verifiedProvenance },
  });
  return {
    surfaced: result.surfaced,
    removedStale: result.removedStale,
    warningCount: result.warnings.length,
  };
}

/**
 * Check if exploitation should run for a given vulnerability type.
 *
 * Uses existing container if available (from prior agent runs),
 * otherwise creates service directly (stateless, no dependencies).
 */
export async function checkExploitationQueue(input: ActivityInput, vulnType: VulnType): Promise<ExploitationDecision> {
  const { repoPath, workflowId } = input;
  const logger = createActivityLogger();

  // Reuse container's service if available (from prior vuln agent runs)
  const existingContainer = getContainer(workflowId);
  const checker = existingContainer?.exploitationChecker ?? new ExploitationCheckerService();

  // Pass deliverablesPath (not repoPath) — validators expect the deliverables directory
  const delivPath = deliverablesDir(repoPath, input.deliverablesSubdir);
  try {
    return await checker.checkQueue(vulnType, delivPath, logger);
  } catch (error) {
    const classified = classifyErrorForTemporal(error);
    const message = truncateErrorMessage(error instanceof Error ? error.message : String(error));
    const details = [{ phase: 'check-exploitation-queue', vulnType }];
    const queueValidationFailure = error instanceof PentestError && error.type === 'validation';
    // A code-less PentestError (e.g. a filesystem read failure) is classified by
    // string-matching, which can miss its retryable flag. Trust the flag directly so
    // a non-retryable error never gets a Temporal retry.
    const pentestNonRetryable = error instanceof PentestError && !error.retryable;

    const failure =
      queueValidationFailure || pentestNonRetryable || !classified.retryable
        ? ApplicationFailure.nonRetryable(
            message,
            queueValidationFailure ? 'InvalidExploitationQueueError' : classified.type,
            details,
          )
        : ApplicationFailure.create({ message, type: classified.type, details });
    truncateStackTrace(failure);
    throw failure;
  }
}

interface SessionJson {
  session: {
    id: string;
    webUrl: string;
    repoPath?: string;
    originalWorkflowId?: string;
    resumeAttempts?: ResumeAttempt[];
  };
  metrics: {
    agents: Record<
      string,
      {
        status: 'in-progress' | 'success' | 'failed';
        checkpoint?: string;
      }
    >;
  };
  durableScanState?: unknown;
}

export interface ResumeLoadOptions {
  readonly deliverablesSubdir?: string;
  readonly expectedExploit?: boolean;
}

/**
 * Load resume state from an existing workspace.
 *
 * Every completion signal here is cross-checked against independent evidence (a deliverable
 * file on disk, a git checkpoint, the durable scan-state record) rather than trusted from
 * session.json alone, because a crash can leave the metrics ledger and the filesystem
 * disagreeing about what actually finished.
 */
export async function loadResumeState(
  workspaceName: string,
  expectedUrl: string,
  expectedRepoPath: string,
  optionsOrDeliverablesSubdir?: ResumeLoadOptions | string,
): Promise<ResumeState> {
  const options: ResumeLoadOptions =
    typeof optionsOrDeliverablesSubdir === 'string'
      ? { deliverablesSubdir: optionsOrDeliverablesSubdir }
      : (optionsOrDeliverablesSubdir ?? {});
  const deliverablesSubdir = options.deliverablesSubdir;
  // 1. Validate workspace exists (prefers .shannon/, falls back to legacy run-root layout)
  const sessionPath = resolveSessionJsonPath(path.join('./workspaces', workspaceName));

  const exists = await fileExists(sessionPath);
  if (!exists) {
    throw ApplicationFailure.nonRetryable(SAFE_RUN_STATE_MESSAGES.CorruptedSessionError, 'WorkspaceNotFoundError', [
      { checkCode: 'session-json-missing' },
    ]);
  }

  // 2. Parse session.json and validate URL match
  let session: SessionJson;
  try {
    session = await readJson<SessionJson>(sessionPath);
  } catch (error) {
    throw ApplicationFailure.nonRetryable(SAFE_RUN_STATE_MESSAGES.CorruptedSessionError, 'CorruptedSessionError', [
      { checkCode: 'session-json-not-json' },
    ]);
  }

  if (!isDurableScanState(session.durableScanState)) {
    // A missing record means a different release wrote this workspace; a malformed one
    // means the record itself is damaged. Each refusal keeps its own wording.
    const durableStateMissing = session.durableScanState === undefined;
    throw ApplicationFailure.nonRetryable(
      durableStateMissing
        ? SAFE_RUN_STATE_MESSAGES.IncompatibleWorkspaceError
        : SAFE_RUN_STATE_MESSAGES.CorruptedSessionError,
      durableStateMissing ? 'IncompatibleWorkspaceError' : 'CorruptedSessionError',
      [{ checkCode: durableStateMissing ? 'durable-state-missing' : 'durable-state-malformed' }],
    );
  }
  let durableState: DurableScanState = structuredClone(session.durableScanState);
  if (options.expectedExploit !== undefined && durableState.exploit !== options.expectedExploit) {
    throw ApplicationFailure.nonRetryable(
      workspaceExploitMismatchMessage(durableState.exploit),
      'IncompatibleWorkspaceError',
      [{ checkCode: 'exploit-mode-changed' }],
    );
  }

  if (session.session.webUrl !== expectedUrl) {
    throw ApplicationFailure.nonRetryable(
      'This workspace was created for a different target URL, so it cannot be resumed against this one. Check -u, or start a new scan with a different -w name.',
      'URLMismatchError',
    );
  }

  // 3. Cross-check agent status with deliverables on disk
  const completedAgents: AgentName[] = [];
  const agents = session.metrics.agents;
  const deliverablesPath = deliverablesDir(expectedRepoPath, deliverablesSubdir);

  const miscellaneousAgentSucceeded = agents['miscellaneous-exploit']?.status === 'success';
  if (miscellaneousAgentSucceeded !== (durableState.miscellaneous_outcome === 'completed')) {
    throw ApplicationFailure.nonRetryable(
      'The admitted miscellaneous-agent state conflicts with persisted metrics.',
      'CorruptedSessionError',
      [{ checkCode: 'miscellaneous-outcome-metrics-divergence' }],
    );
  }
  const reportAgentSucceeded = agents.report?.status === 'success';
  if (reportAgentSucceeded !== (durableState.report?.stage === 'finalized')) {
    throw ApplicationFailure.nonRetryable(
      'The report terminal state conflicts with persisted metrics.',
      'CorruptedSessionError',
      [{ checkCode: 'report-stage-metrics-divergence' }],
    );
  }

  if (durableState.report?.stage === 'draft') {
    const draftValidation = await validateDraftProgress(deliverablesPath, durableState.report);
    if (draftValidation === 'invalid-model') {
      await rollbackInvalidReportDraft(
        {
          webUrl: expectedUrl,
          repoPath: expectedRepoPath,
          workflowId: session.session.originalWorkflowId ?? session.session.id,
          sessionId: workspaceName,
          ...(deliverablesSubdir !== undefined && { deliverablesSubdir }),
        },
        durableState.report,
      );
      durableState = {
        ...durableState,
        report: {
          stage: 'pending',
          renumber_failed_classes: [...durableState.report.renumber_failed_classes],
          partial_reasons: [...durableState.report.partial_reasons],
        },
      };
    } else if (draftValidation === 'invalid-canonical') {
      throw ApplicationFailure.nonRetryable('The canonical report checkpoint is invalid.', 'CorruptedSessionError', [
        { checkCode: 'report-canonical-checkpoint-invalid' },
      ]);
    }
  }
  if (
    durableState.report?.stage === 'finalized' &&
    !(await finalProgressIsCoherent(deliverablesPath, durableState.report))
  ) {
    throw ApplicationFailure.nonRetryable('The terminal report checkpoint proof is invalid.', 'CorruptedSessionError', [
      { checkCode: 'report-final-proof-invalid' },
    ]);
  }

  for (const agentName of durableState.expected_agents) {
    if (agentName === 'report') {
      if (durableState.report?.stage === 'finalized') completedAgents.push(agentName);
      continue;
    }
    const agentData = agents[agentName];
    if (!agentData || agentData.status !== 'success') {
      continue;
    }

    const deliverableFilename = AGENTS[agentName].deliverableFilename;
    const deliverablePath = path.join(deliverablesDir(expectedRepoPath, deliverablesSubdir), deliverableFilename);
    const deliverableExists = await fileExists(deliverablePath);

    if (!deliverableExists) {
      const logger = createActivityLogger();
      logger.warn(`Agent ${agentName} shows success but deliverable missing, will re-run`);
      continue;
    }

    completedAgents.push(agentName);
  }

  // 4. Collect git checkpoints and validate at least one exists
  const checkpoints = completedAgents
    .map((name) => agents[name]?.checkpoint)
    .filter((hash): hash is string => hash != null);
  for (const [stage, progress] of Object.entries(durableState.post_exploitation ?? {})) {
    if (progress?.status !== 'completed') continue;
    try {
      await validatePostExploitationCheckpoint(deliverablesPath, stage as PostExploitationStage, progress);
    } catch (error) {
      if (error instanceof RunStateError) throw runStateFailure(error);
      throw error;
    }
    checkpoints.push(progress.checkpoint);
  }
  if (durableState.report?.stage === 'draft') {
    checkpoints.push(durableState.report.model_checkpoint);
    if (durableState.report.canonical_checkpoint !== undefined) {
      checkpoints.push(durableState.report.canonical_checkpoint);
    }
  }
  if (durableState.report?.stage === 'finalized') checkpoints.push(durableState.report.final_checkpoint);

  if (checkpoints.length === 0) {
    const successAgents = Object.entries(agents)
      .filter(([, data]) => data.status === 'success')
      .map(([name]) => name);

    throw ApplicationFailure.nonRetryable(
      `Cannot resume workspace ${workspaceName}: ` +
        (successAgents.length > 0
          ? `${successAgents.length} agent(s) show success in session.json (${successAgents.join(', ')}) ` +
            `but their deliverable files are missing from disk. ` +
            `Start a fresh run instead.`
          : `No agents completed successfully. Start a fresh run instead.`),
      'NoCheckpointsError',
    );
  }

  // 5. Find the most recent checkpoint commit
  const checkpointHash = await findLatestCommit(deliverablesPath, checkpoints);
  const originalWorkflowId = session.session.originalWorkflowId || session.session.id;

  // 6. Log summary and return resume state
  const logger = createActivityLogger();
  logger.info('Resume state loaded', {
    workspace: workspaceName,
    completedAgents: completedAgents.length,
    checkpoint: checkpointHash,
  });

  return {
    workspaceName,
    originalUrl: session.session.webUrl,
    completedAgents,
    checkpointHash,
    originalWorkflowId,
    expectedAgents: [...durableState.expected_agents],
    participatingClasses: [...durableState.participating_classes],
    exploit: durableState.exploit,
    ...(durableState.report !== undefined && { reportProgress: structuredClone(durableState.report) }),
    ...(durableState.miscellaneous_outcome !== undefined && {
      miscellaneousOutcome: durableState.miscellaneous_outcome,
    }),
  };
}

/** Transitional workflow signature backed by the durable initializer, never by static reconstruction. */
export async function persistOrValidateRunScope(
  input: ActivityInput,
  vulnClasses: VulnClass[],
  exploit: boolean,
): Promise<void> {
  try {
    assertFixedAnalysisScope(vulnClasses);
  } catch (error) {
    throw runStateFailure(error);
  }
  if (input.stateContext === undefined) {
    throw ApplicationFailure.nonRetryable(
      'The workflow must identify fresh or resume initialization explicitly.',
      'IncompatibleWorkspaceError',
      [{ checkCode: 'state-context-missing' }],
    );
  }
  await initializeDurableScanState(input, exploit, input.stateContext);
}

async function findLatestCommit(gitDir: string, commitHashes: string[]): Promise<string> {
  if (commitHashes.length === 1) {
    const hash = commitHashes[0];
    if (!hash) {
      throw new PentestError(
        'Empty commit hash in array',
        'filesystem',
        false, // Non-retryable - corrupt workspace state
        { phase: 'resume' },
        ErrorCode.GIT_CHECKPOINT_FAILED,
      );
    }
    return hash;
  }

  const result = await executeGitCommandWithRetry(
    ['git', 'rev-list', '--max-count=1', ...commitHashes],
    gitDir,
    'find latest commit',
  );

  return result.stdout.trim();
}

/**
 * Restore deliverables git to a checkpoint.
 * Operates on the private git inside workspace deliverables, not the user's repo.
 */
export async function restoreGitCheckpoint(
  repoPath: string,
  checkpointHash: string,
  incompleteAgents: AgentName[],
  deliverablesSubdir?: string,
  durable?: {
    readonly expectedAgents: readonly AgentName[];
    readonly participatingClasses: readonly ReconciliationClass[];
    readonly reportProgress?: ReportProgress;
  },
): Promise<void> {
  // Restore membership must come from the durable scan-state record, never be reconstructed
  // from the caller's own agent list, so a corrupted or stale caller can never make this
  // activity delete deliverables that are still needed.
  if (durable === undefined) {
    throw ApplicationFailure.nonRetryable(
      'Persisted restore membership is required before workspace mutation.',
      'IncompatibleWorkspaceError',
      [{ checkCode: 'restore-durable-membership-missing' }],
    );
  }
  const expectedAgents = durable.expectedAgents;
  const exploitOff = initialExpectedAgents(false);
  const exploitOn = initialExpectedAgents(true);
  const expectedSetIsValid =
    arraysEqual(expectedAgents, exploitOff) ||
    arraysEqual(expectedAgents, exploitOn) ||
    arraysEqual(expectedAgents, [...exploitOn, 'miscellaneous-exploit']);
  const participatingClasses = durable.participatingClasses;
  const participatingSetIsValid =
    arraysEqual(participatingClasses, FIXED_ANALYSIS_CLASSES) ||
    arraysEqual(participatingClasses, [...FIXED_ANALYSIS_CLASSES, 'miscellaneous']);
  const miscellaneousAdmissionIsValid =
    !expectedAgents.includes('miscellaneous-exploit') || participatingClasses.includes('miscellaneous');
  if (
    !expectedSetIsValid ||
    !participatingSetIsValid ||
    !miscellaneousAdmissionIsValid ||
    (durable.reportProgress !== undefined && !isReportProgress(durable.reportProgress, participatingClasses))
  ) {
    throw ApplicationFailure.nonRetryable(
      'Persisted restore membership or report state is malformed.',
      'CorruptedSessionError',
      [{ checkCode: 'restore-durable-input-malformed' }],
    );
  }

  const deliverablesPath = deliverablesDir(repoPath, deliverablesSubdir);
  const logger = createActivityLogger();
  logger.info(`Restoring deliverables to ${checkpointHash}...`);

  // Validate the hash exists in the deliverables clone (the repo actually being
  // reset below) before attempting reset.
  try {
    await executeGitCommandWithRetry(
      ['git', 'cat-file', '-e', `${checkpointHash}^{commit}`],
      deliverablesPath,
      'verify checkpoint hash exists',
    );
  } catch {
    logger.info(`Checkpoint hash not found in clone, skipping git reset: ${checkpointHash}`);
    return;
  }

  await executeGitCommandWithRetry(
    ['git', 'reset', '--hard', checkpointHash],
    deliverablesPath,
    'reset deliverables to checkpoint',
  );

  // Scope the untracked clean so a completed agent's deliverables survive: exclude every
  // completed agent's paths, cleaning only leftovers from the incomplete agents being re-run.
  const incompleteSet = new Set<AgentName>(incompleteAgents);
  if (durable?.reportProgress?.stage === 'draft' || durable?.reportProgress?.stage === 'finalized') {
    incompleteSet.delete('report');
  }
  const completedPaths = expectedAgents.filter((name) => !incompleteSet.has(name)).flatMap(getAgentGitPaths);
  const cleanArgs = ['git', 'clean', '-fd', ...completedPaths.flatMap((completedPath) => ['-e', completedPath])];
  await executeGitCommandWithRetry(cleanArgs, deliverablesPath, 'clean untracked deliverables');

  // Explicitly delete partial deliverables for incomplete agents
  for (const agentName of incompleteAgents) {
    if (agentName === 'report' && !incompleteSet.has('report')) continue;
    const deliverableFilename = AGENTS[agentName].deliverableFilename;
    const deliverablePath = path.join(deliverablesPath, deliverableFilename);
    try {
      const exists = await fileExists(deliverablePath);
      if (exists) {
        logger.warn(`Cleaning partial deliverable: ${agentName}`);
        await fs.unlink(deliverablePath);
      }
    } catch (error) {
      logger.info(`Note: Failed to delete ${deliverablePath}: ${error}`);
    }
  }

  logger.info('Deliverables restored to clean state');
}

/**
 * Record a resume attempt in session.json and write resume header to workflow.log.
 */
/**
 * Register this resume's workflow id in session.json before loadResumeState (which can throw),
 * so the CLI can resolve and follow the resume even when validation fails instead of timing out.
 */
export async function registerResumeAttempt(input: ActivityInput, terminatedWorkflows: string[]): Promise<void> {
  const sessionMetadata = buildSessionMetadata(input);
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize(input.workflowId);
  await auditSession.logResumeBoundary(input.workflowId);
  await auditSession.addResumeAttempt(input.workflowId, terminatedWorkflows);
}

export async function recordResumeAttempt(
  input: ActivityInput,
  checkpointHash: string,
  previousWorkflowId: string,
  completedAgents: string[],
): Promise<void> {
  const sessionMetadata = buildSessionMetadata(input);
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize();

  // The execution boundary was flushed by registerResumeAttempt before session.json publication.
  await auditSession.logResumeDetails({
    previousWorkflowId,
    newWorkflowId: input.workflowId,
    checkpointHash,
    completedAgents,
  });
}

/**
 * Log phase transition to the unified workflow log.
 */
export async function logPhaseTransition(
  input: ActivityInput,
  phase: WorkflowPhase,
  event: 'start' | 'complete',
): Promise<void> {
  const sessionMetadata = buildSessionMetadata(input);
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize(input.workflowId);

  if (event === 'start') {
    await auditSession.logPhaseStart(phase);
  } else {
    await auditSession.logPhaseComplete(phase);
  }
}

/**
 * Log workflow completion with full summary.
 * Cleans up container when done.
 */
export async function logWorkflowComplete(input: ActivityInput, summary: WorkflowSummary): Promise<void> {
  const { workflowId } = input;
  const sessionMetadata = buildSessionMetadata(input);

  // 1. Initialize the audit session. The terminal write below owns both status and totals.
  const auditSession = new AuditSession(sessionMetadata);
  await auditSession.initialize(workflowId);

  // 2. Operational work has no independent audit-session writer, so this terminal
  // projection is its durable source of truth.
  const totals = await auditSession.recordTerminalWorkflowMetrics(workflowId, {
    status: summary.status,
    startedAtMs: summary.startedAtMs,
    endedAtMs: summary.endedAtMs,
    usageAccountingComplete: summary.usageAccountingComplete !== false,
    usageAccountingWarnings: summary.usageAccountingWarnings ?? [],
    operationalMetrics: summary.operationalMetrics,
    // The priced metrics carry cost but no faithful duration, so the stage spans are the only
    // source of operational wall-clock. The tracker keeps the operational families and drops
    // the rest.
    operationalStages: summary.operationalStages,
  });

  // 3. Load the now-current cumulative agent ledger from session.json.
  const sessionData = (await auditSession.getMetrics()) as {
    metrics: {
      agents: Record<string, { final_duration_ms: number; total_cost_usd: number }>;
    };
  };

  // 4. Fill in metrics for skipped agents that completed in an earlier workflow run.
  const agentMetrics = { ...summary.agentMetrics };
  for (const agentName of summary.completedAgents) {
    if (!agentMetrics[agentName]) {
      const agentData = sessionData.metrics.agents[agentName];
      if (agentData) {
        agentMetrics[agentName] = {
          durationMs: agentData.final_duration_ms,
          costUsd: agentData.total_cost_usd,
        };
      }
    }
  }

  // 5. Log the cumulative workspace totals. Duration is elapsed workflow time, while the
  // separate total_agent_duration_ms in session.json remains the sum of agent work.
  const cumulativeSummary: WorkflowSummary = {
    ...summary,
    totalDurationMs: totals.totalDurationMs,
    totalCostUsd: totals.totalCostUsd,
    usageAccountingComplete: totals.usageAccountingComplete,
    agentMetrics,
  };

  // 6. Write completion entry to workflow.log
  await auditSession.logWorkflowComplete(cumulativeSummary);

  // 7. Drop the authenticated browser session. auth-state.json holds live cookies/storage for
  // the lifetime of the scan only; leaving it on disk past workflow end would let a session
  // outlive the run that created it. The removal is best-effort: a failure here is logged and
  // swallowed rather than failing a scan that otherwise completed successfully.
  try {
    await fs.rm(authStateFile(sessionMetadata), { force: true });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.warn(`Failed to clean up auth-state.json: ${detail}`);
  }

  // 8. Clean up container
  removeContainer(workflowId);
}

/**
 * Merge external findings into the exploitation queue for a vulnerability type.
 *
 * Delegates to the FindingsProvider registered in the DI container.
 * Default: no-op returning { mergedCount: 0 }.
 * Consumers can override this activity at the worker level with custom findings integration.
 */
export async function mergeFindingsIntoQueue(
  input: ActivityInput,
  vulnType: VulnType,
): Promise<{ mergedCount: number }> {
  const container = getContainer(input.workflowId);
  if (!container?.findingsProvider) return { mergedCount: 0 };
  return container.findingsProvider.mergeFindingsIntoQueue(input.repoPath, vulnType, input);
}

/**
 * Persist pipeline state after an agent completes.
 *
 * Delegates to the CheckpointProvider registered in the DI container.
 * Default: no-op. Consumers can override this activity at the worker level with custom persistence.
 */
export async function saveCheckpoint(
  input: ActivityInput,
  agentName: string,
  phase: string,
  state: PipelineState,
): Promise<void> {
  const container = getContainer(input.workflowId);
  if (!container?.checkpointProvider) return;

  const context: CheckpointContext = {
    repoPath: input.repoPath,
    sessionId: input.sessionId,
    deliverablesSubdir: input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
    ...(input.outputPath !== undefined && { outputPath: input.outputPath }),
  };

  return container.checkpointProvider.onAgentComplete(agentName, phase, state, context);
}
