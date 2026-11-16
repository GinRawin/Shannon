// Copyright (C) 2026 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Identification Shannon sends on every outbound request during an assessment so
 * the target's operators can recognise the traffic as an authorised test. Defined
 * once here and reused by the agent browser config, host browser replay, and the
 * curl capture/replay paths.
 */

import { curlArguments } from './services/curl-invocation.js';

export const SHANNON_USER_AGENT = 'Shannon-huangjingren';

const USER_AGENT_HEADER = /^\s*user-agent\s*[:;]/i;

/** Whether a curl invocation already selects its own User-Agent, by -A or by header. */
export function curlInvocationSetsUserAgent(argv: readonly string[]): boolean {
  return curlArguments(argv).arguments.some(
    (argument) =>
      argument.option === 'user-agent' ||
      (argument.option === 'header' && USER_AGENT_HEADER.test(argument.value ?? '')),
  );
}

/**
 * Prepend the identification User-Agent to a curl invocation that does not choose
 * one, so an operator-supplied -A or User-Agent header is never overridden.
 */
export function withCurlUserAgent(argv: readonly string[], userAgent = SHANNON_USER_AGENT): string[] {
  return curlInvocationSetsUserAgent(argv) ? [...argv] : ['--user-agent', userAgent, ...argv];
}
