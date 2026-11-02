// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/** Generic child-session delegation for the pi harness. */

import { appendFile } from 'node:fs/promises';
import path from 'node:path';
import { type AssistantMessage, type Model, Type } from '@earendil-works/pi-ai';
import {
  createAgentSession,
  defineTool,
  getAgentDir,
  type ModelRuntime,
  type ResourceLoader,
  SessionManager,
  SettingsManager,
  type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { type LoggableAgentName, normalizeSemanticLabel } from '../../audit/safe-fields.js';
import { classifyProviderFailure, PentestError } from '../../services/error-handling.js';
import { ErrorCode } from '../../types/errors.js';
import { PI_RETRY_SETTINGS } from './retry-settings.js';
import { TraceEmitter } from './trace-emitter.js';
import {
  providerTurnError,
  type SafeExecutionFailureDetails,
  type SafeProviderTurnDetails,
  safeExecutionFailureDetails,
  safeProviderTurnDetails,
} from './turn-error.js';

export interface TaskToolContext {
  readonly cwd: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  readonly model: Model<any>;
  readonly modelRuntime: ModelRuntime;
  readonly createResourceLoader: () => Promise<ResourceLoader>;
  /** Children can capture their own validation; only the parent submits verdicts. */
  readonly httpEvidenceTools?: ToolDefinition[] | undefined;
  readonly parentAgentName: LoggableAgentName;
  readonly workflowLogPath?: string | undefined;
  readonly onDelegationStart?: ((child: string) => Promise<void>) | undefined;
  /** Unresolved child failures fail the parent; an explicit successful retry resolves only its own failure. */
  readonly onFailure?: (error: PentestError, details?: SafeProviderTurnDetails) => void;
  readonly onRecovery?: (error: PentestError) => void;
  readonly cancellationSignal?: AbortSignal | undefined;
  readonly onUsage?: (usage: {
    readonly cost: number;
    readonly inputTokens: number;
    readonly outputTokens: number;
    readonly cacheReadTokens: number;
    readonly cacheWriteTokens: number;
  }) => void;
}

// Deliberately excludes `task` (no recursive delegation, so a child cannot spawn further children)
// and collector/submit tools (structured verdicts stay owned by the top-level agent
// session). HTTP evidence tools are shared so a child can capture its original proof.
const CHILD_TOOLS = ['read', 'grep', 'find', 'ls', 'write', 'bash'];
const CHILD_FAILURE_TEXT = '[Sub-agent task failed before completion]';
const CHILD_CANCELLED_TEXT = '[Sub-agent task was cancelled]';

function textResult(text: string) {
  return { content: [{ type: 'text' as const, text }], details: undefined };
}

function childTaskError(error: unknown): PentestError {
  if (error instanceof PentestError) return error;
  const failure = classifyProviderFailure(error);
  const result = new PentestError(failure.message, 'unknown', failure.retryable, {}, ErrorCode.AGENT_EXECUTION_FAILED);
  result.providerCategory = failure.category;
  return result;
}

/**
 * Assigns each child a stable, safe display identity from its description. A duplicate of a
 * live sibling's name gets a monotonic start-order suffix (`route mapper #2`); a missing or
 * unsafe description becomes `subagent N`. State is shared across one parent's task calls,
 * and the assignment block runs synchronously so parallel calls never race on it.
 */
// Keep the base short enough that a `#N` suffix still fits the identity validator's length
// bound (48); a longer description falls back to `subagent N` rather than being dropped.
const MAX_CHILD_BASE_LENGTH = 40;

function createChildNamer(): (description: unknown) => string {
  const namedCounts = new Map<string, number>();
  let anonymousCount = 0;
  return (description) => {
    const base = normalizeSemanticLabel(description);
    if (base === undefined || base.length > MAX_CHILD_BASE_LENGTH) {
      anonymousCount += 1;
      return `subagent ${anonymousCount}`;
    }
    const nextOrdinal = (namedCounts.get(base) ?? 0) + 1;
    namedCounts.set(base, nextOrdinal);
    return nextOrdinal === 1 ? base : `${base} #${nextOrdinal}`;
  };
}

export function createTaskTool(config: TaskToolContext): ToolDefinition {
  const nameChild = createChildNamer();
  const logPath = config.workflowLogPath;
  const failures = new Map<string, { error: PentestError; retryOf?: string }>();

  const resolveFailure = (taskId: string): void => {
    const failure = failures.get(taskId);
    if (failure === undefined) return;
    failures.delete(taskId);
    config.onRecovery?.(failure.error);
    if (failure.retryOf !== undefined) resolveFailure(failure.retryOf);
  };

  return defineTool({
    name: 'task',
    label: 'Task',
    description:
      'Delegate a focused task to a sub-agent that runs independently with its own tools and returns ' +
      'the result. Use this to break complex work into smaller, parallelizable sub-tasks.',
    executionMode: 'parallel',
    promptSnippet: 'task - Delegate a focused task to a sub-agent with read, grep, find, ls, write, and bash.',
    promptGuidelines: [
      'Use the task tool to delegate focused work: code review, reconnaissance, automation scripting, validation.',
      'Pass all necessary context in the "prompt" parameter — the sub-agent cannot see your conversation history.',
      'The sub-agent can use read, grep, find, ls, write, and bash, plus HTTP evidence tools when provided. It cannot call task or verdict collector tools. Tell it to return capture IDs with its proof.',
      'You can launch multiple task tool calls in a single message to run sub-tasks in parallel.',
      'If a task fails, retry or reassign the same required work with retry_of set to the task ID returned in its failure. A successful retry clears that failure; unrelated tasks do not. Unresolved failures prevent the parent stage from succeeding.',
    ],
    parameters: Type.Object({
      prompt: Type.String({
        description: 'The task for the sub-agent to perform. Include all necessary context.',
      }),
      description: Type.Optional(Type.String({ description: 'A short (3-5 word) description of the task.' })),
      retry_of: Type.Optional(
        Type.String({ description: 'Task ID of the failed task whose required work this retry replaces.' }),
      ),
    }),
    async execute(toolCallId, params) {
      // Assign the identity synchronously, before any await, so concurrent siblings can't race.
      const child = nameChild(params.description);
      if (params.retry_of !== undefined && !failures.has(params.retry_of)) {
        return textResult('[Invalid retry_of: use the task ID returned by an unresolved failed task.]');
      }
      const emitter = logPath
        ? new TraceEmitter(logPath, { kind: 'child', parent: config.parentAgentName, child })
        : undefined;
      const startedAt = Date.now();

      // The parent's emitter first writes the raw task invocation, then this delegation
      // record. Awaiting it prevents the child emitter from overtaking its lineage start.
      await config.onDelegationStart?.(child);

      const agentDir = getAgentDir();
      let subSession: Awaited<ReturnType<typeof createAgentSession>>['session'] | undefined;
      let resultText = '';
      let subCost = 0;
      let turns = 0;
      let operations = 0;
      let failed = false;
      let fatalFailure = false;
      let providerFailure: SafeProviderTurnDetails | undefined;
      let compactionFailed = false;
      let executionFailure: PentestError | undefined;
      let failureDetails: SafeExecutionFailureDetails | undefined;

      const abortChildSession = (): void => {
        void subSession?.abort().catch(() => {
          // Dispose below still tears down the child session.
        });
      };
      const onCancellation = (): void => abortChildSession();

      try {
        const resourceLoader = await config.createResourceLoader();
        ({ session: subSession } = await createAgentSession({
          cwd: config.cwd,
          agentDir,
          resourceLoader,
          model: config.model,
          tools: [...CHILD_TOOLS, ...(config.httpEvidenceTools ?? []).map((tool) => tool.name)],
          customTools: config.httpEvidenceTools ?? [],
          modelRuntime: config.modelRuntime,
          sessionManager: SessionManager.inMemory(config.cwd),
          settingsManager: SettingsManager.inMemory({
            retry: PI_RETRY_SETTINGS,
            compaction: { enabled: true },
          }),
        }));

        if (config.cancellationSignal?.aborted) {
          abortChildSession();
        } else {
          config.cancellationSignal?.addEventListener('abort', onCancellation, { once: true });
        }

        subSession.subscribe((event) => {
          if (event.type === 'compaction_end' && !event.aborted && !event.willRetry && event.errorMessage) {
            compactionFailed = true;
            failed = true;
            failureDetails = safeExecutionFailureDetails(event.errorMessage);
            executionFailure = new PentestError(
              'Child context compaction failed.',
              'unknown',
              true,
              {},
              ErrorCode.AGENT_EXECUTION_FAILED,
            );
            return;
          }
          if (event.type === 'tool_execution_start') {
            operations += 1;
            emitter?.toolStart(event.toolCallId, event.toolName, event.args);
            return;
          }
          if (event.type === 'tool_execution_end') {
            emitter?.toolEnd(event.toolCallId, event.isError);
            return;
          }
          if (event.type !== 'turn_end') return;
          turns += 1;
          const message = event.message as AssistantMessage | undefined;
          if (message?.role === 'assistant' && message.stopReason === 'error') {
            failed = true;
            providerFailure = safeProviderTurnDetails(message, config.model.contextWindow);
            executionFailure = providerTurnError(message, 'Child agent error', config.model.contextWindow);
          }
          for (const block of message?.content ?? []) {
            if (block.type === 'text' && block.text) {
              resultText += (resultText ? '\n' : '') + block.text;
            }
          }
          if (message?.usage?.cost?.total != null) subCost += message.usage.cost.total;
        });

        try {
          await subSession.prompt(params.prompt);
        } catch (error) {
          failed = true;
          failureDetails ??= safeExecutionFailureDetails(error);
          executionFailure ??= childTaskError(error);
        }
        if (subSession.state.errorMessage !== undefined) {
          failed = true;
          failureDetails ??= safeExecutionFailureDetails(subSession.state.errorMessage);
          executionFailure ??= childTaskError(new Error(subSession.state.errorMessage));
        }

        const subStats = subSession.getSessionStats();
        if (subStats.cost > subCost) subCost = subStats.cost;
        config.onUsage?.({
          cost: subCost,
          inputTokens: subStats.tokens.input,
          outputTokens: subStats.tokens.output,
          cacheReadTokens: subStats.tokens.cacheRead,
          cacheWriteTokens: subStats.tokens.cacheWrite,
        });
      } catch (error) {
        fatalFailure = true;
        failureDetails ??= safeExecutionFailureDetails(error);
        executionFailure ??= childTaskError(error);
      } finally {
        config.cancellationSignal?.removeEventListener('abort', onCancellation);
        subSession?.dispose();
      }

      const durationMs = Date.now() - startedAt;
      if (config.cancellationSignal?.aborted) {
        emitter?.sessionFailure('CANCELLED', durationMs);
        await emitter?.flush();
        return textResult(CHILD_CANCELLED_TEXT);
      }
      if (fatalFailure || failed) {
        const stage = fatalFailure ? 'create-session' : compactionFailed ? 'compaction' : 'prompt';
        const diagnostic = {
          child,
          stage,
          turns,
          operations,
          ...(providerFailure !== undefined && { providerTurn: providerFailure }),
          ...(failureDetails !== undefined && { execution: failureDetails }),
        };
        console.warn('Child task failed', diagnostic);
        emitter?.sessionFailure('CHILD_TASK_FAILED', durationMs);
        await emitter?.flush();
        const failure = executionFailure ?? childTaskError(new Error(CHILD_FAILURE_TEXT));
        failures.set(toolCallId, {
          error: failure,
          ...(params.retry_of !== undefined && { retryOf: params.retry_of }),
        });
        config.onFailure?.(failure, providerFailure);
        // Persist before the parent's failure handling can roll back its uncommitted output.
        try {
          const dir = process.env.SHANNON_DELIVERABLES_DIR ?? path.join(config.cwd, '.shannon', 'deliverables');
          await appendFile(
            path.join(dir, 'error.log'),
            `${JSON.stringify({
              timestamp: new Date().toISOString(),
              agent: config.parentAgentName,
              error: { code: failure.code, category: failure.providerCategory, retryable: failure.retryable },
              ...diagnostic,
            })}\n`,
          );
        } catch {
          // Best-effort diagnostics must not replace the original failure.
        }
        const reason = providerFailure?.providerCategory ?? (compactionFailed ? 'compaction' : undefined);
        return textResult(
          `${CHILD_FAILURE_TEXT}${reason ? ` (${reason})` : ''}\nTask ID: ${toolCallId}\nRetry or reassign this required work using task with retry_of: ${JSON.stringify(toolCallId)}. This failure remains unresolved until that retry succeeds.`,
        );
      }

      if (params.retry_of !== undefined) resolveFailure(params.retry_of);
      emitter?.sessionComplete(durationMs, turns, operations);
      await emitter?.flush();
      return textResult(resultText || '[Sub-agent produced no output]');
    },
  });
}
