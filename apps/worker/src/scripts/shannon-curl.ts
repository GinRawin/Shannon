#!/usr/bin/env node
// Copyright (C) 2026 Keygraph, Inc.
//
// Capture a curl HTTP exchange during exploitation while preserving curl's
// normal stdout, stderr, exit status, and request semantics.

import { captureHttpRequest, validateCurlCaptureArguments } from '../services/capture-http-request.js';

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
