#!/usr/bin/env node
// Copyright (C) 2026 Keygraph, Inc.
//
// Capture a curl HTTP exchange during exploitation while preserving curl's
// normal stdout, stderr, exit status, and request semantics.

import { captureHttpRequest, validateCurlCaptureArguments } from '../services/capture-http-request.js';
import { captureViaBridge } from '../services/http-capture-bridge.js';

function usage(): never {
  process.stderr.write('Usage: shannon-curl --finding-id ID -- <curl arguments...>\n');
  process.exit(2);
}

const args = process.argv.slice(2);
const idFlag = args.indexOf('--finding-id');
const separator = args.indexOf('--');
if (idFlag < 0 || separator < 0 || idFlag + 1 >= separator) usage();
const findingId = args[idFlag + 1] as string;
if (!/^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(findingId)) usage();
const curlArgs = args.slice(separator + 1);
if (curlArgs.length === 0) usage();
try {
  validateCurlCaptureArguments(curlArgs);
} catch {
  usage();
}

const deliverablesDir = process.env.SHANNON_DELIVERABLES_DIR;
if (!deliverablesDir) {
  process.stderr.write('SHANNON_DELIVERABLES_DIR is not set; HTTP capture was not saved.\n');
  process.exit(2);
}

if (process.env.SHANNON_CAPTURE_SOCKET) {
  try {
    const result = await captureViaBridge(process.env.SHANNON_CAPTURE_SOCKET, {
      directory: deliverablesDir,
      finding_id: findingId,
      curl_arguments: curlArgs,
      cwd: process.cwd(),
    });
    if (result.status !== 'success') throw new Error(result.message ?? 'Host capture failed');
    process.stdout.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    process.stderr.write(`\nHTTP evidence saved: ${result.capture_id} (${result.file})\n`);
    process.exit(result.exit_code ?? 1);
  } catch (error) {
    process.stderr.write(`HTTP capture failed: ${(error as Error).message}\n`);
    process.exit(2); // Never resend via a fallback after a host request may have executed.
  }
}

const captured = await captureHttpRequest({
  deliverablesDir,
  findingId,
  curlArguments: curlArgs,
  onStdout: (data) => {
    process.stdout.write(data);
  },
  onStderr: (data) => {
    process.stderr.write(data);
  },
});
process.stderr.write(`\nHTTP evidence saved: ${captured.receipt.capture_id} (${captured.receipt.file})\n`);
process.exitCode = captured.receipt.exit_code;
