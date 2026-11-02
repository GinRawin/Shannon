// Copyright (C) 2026 Keygraph, Inc.
// The same constrained HTTP runner verifies PoCs in the worker and in reproduce.sh.

import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { Type } from 'typebox';
import { Value } from 'typebox/value';
import { type HttpEvidenceReceipt, persistCapturedTrace } from './capture-http-request.js';
import { snapshotCurlInvocation } from './curl-invocation.js';

const StepSchema = Type.Object({
  method: Type.Union(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((value) => Type.Literal(value))),
  url: Type.String({
    minLength: 1,
    // biome-ignore lint/suspicious/noTemplateCurlyInString: These are literal runtime placeholders in replay plans.
    description: 'HTTP URL starting with ${BASE_URL}. Supports ${VARIABLE} substitution.',
  }),
  headers: Type.Optional(Type.Record(Type.String(), Type.String())),
  body: Type.Optional(Type.String()),
  body_json: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
  multipart: Type.Optional(
    Type.Array(
      Type.Object(
        {
          name: Type.String({ minLength: 1, pattern: '^[A-Za-z0-9_.-]+$' }),
          value: Type.String({
            // biome-ignore lint/suspicious/noTemplateCurlyInString: literal runtime placeholder syntax.
            description: 'Literal field value or file contents; supports ${VARIABLE} substitution.',
          }),
          filename: Type.Optional(Type.String({ minLength: 1, pattern: '^[A-Za-z0-9_.-]+$' })),
          content_type: Type.Optional(Type.String({ pattern: '^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$' })),
        },
        { additionalProperties: false },
      ),
      {
        minItems: 1,
        maxItems: 20,
        description:
          'Multipart fields. For a file part, set filename and optionally content_type; at most one file part is supported. Do not set a Content-Type header; curl creates the boundary.',
      },
    ),
  ),
  follow_redirects: Type.Optional(Type.Boolean()),
  insecure: Type.Optional(Type.Boolean()),
  expect: Type.Optional(
    Type.Object({
      status: Type.Integer({ minimum: 100, maximum: 599 }),
      body_contains: Type.String({
        minLength: 1,
        description: 'A concrete substring demonstrating the claimed impact, not a generic success message.',
      }),
    }),
  ),
  save_json: Type.Optional(
    Type.Record(
      Type.String(),
      Type.String({ minLength: 1, description: 'Response JSON path, e.g. data.token or users.0.id.' }),
    ),
  ),
  save_headers: Type.Optional(Type.Record(Type.String(), Type.String({ minLength: 1 }))),
});

export const HttpReplaySchema = Type.Object({
  setup: Type.Optional(Type.Array(StepSchema, { maxItems: 20 })),
  steps: Type.Array(StepSchema, { minItems: 1, maxItems: 50 }),
  cleanup: Type.Optional(Type.Array(StepSchema, { maxItems: 20 })),
});

export interface HttpReplayStep {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  body_json?: Record<string, unknown>;
  multipart?: Array<{ name: string; value: string; filename?: string; content_type?: string }>;
  follow_redirects?: boolean;
  insecure?: boolean;
  expect?: { status: number; body_contains: string };
  save_json?: Record<string, string>;
  save_headers?: Record<string, string>;
}
export interface HttpReplayPlan {
  setup?: HttpReplayStep[];
  steps: HttpReplayStep[];
  cleanup?: HttpReplayStep[];
}
export interface HttpReplayVerification {
  plan_sha256: string;
  verified_at: string;
  request_count: number;
  assertion_count: number;
}
export const REPLAY_VARIABLES = ['BASE_URL', 'BEARER_TOKEN', 'COOKIE', 'USERNAME', 'PASSWORD', 'OTP'] as const;

export function replayPlanDigest(plan: HttpReplayPlan): string {
  return createHash('sha256').update(JSON.stringify(plan)).digest('hex');
}

/** Reject plans whose source request was not fully translated into replay fields. */
export function replayPlanError(plan: HttpReplayPlan): string | undefined {
  if (!Value.Check(HttpReplaySchema, plan)) return 'Replay plan does not match the supported HTTP request schema.';
  for (const [index, step] of [...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])].entries()) {
    const label = `Request ${index + 1}`;
    // biome-ignore lint/suspicious/noTemplateCurlyInString: literal runtime placeholder syntax.
    if (!step.url.startsWith('${BASE_URL}')) return `${label} URL must begin with \${BASE_URL}.`;
    if (step.follow_redirects) return `${label} cannot follow redirects during replay.`;
    const serialized = JSON.stringify({
      url: step.url,
      headers: step.headers,
      body: step.body,
      body_json: step.body_json,
      multipart: step.multipart,
      expect: step.expect,
    });
    if (/\[[A-Z][A-Z0-9_ -]*\]|\{\{[^{}]+\}\}/.test(serialized))
      return `${label} contains an unresolved placeholder; replace it with a literal or a \${VARIABLE}.`;
    if (Number('body' in step) + Number('body_json' in step) + Number('multipart' in step) > 1)
      return `${label} must use only one request body format.`;
    if (step.body?.startsWith('--')) {
      const boundary = step.body.match(/^--([^\r\n]+)\r?\n/)?.[1];
      const contentType = Object.entries(step.headers ?? {}).find(
        ([name]) => name.toLowerCase() === 'content-type',
      )?.[1];
      const declared = contentType?.match(/(?:^|;)\s*boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
      if (
        boundary &&
        (!contentType ||
          !/^multipart\/form-data\s*;/i.test(contentType) ||
          (declared?.[1] ?? declared?.[2]) !== boundary)
      )
        return `${label} has a raw multipart body without a matching Content-Type boundary; use multipart fields instead.`;
    }
    if (step.multipart) {
      if (step.multipart.filter((part) => part.filename !== undefined).length > 1)
        return `${label} multipart supports at most one file part.`;
      if (step.multipart.some((part) => part.content_type && !part.filename))
        return `${label} content_type is only supported on a multipart file part.`;
      if (Object.keys(step.headers ?? {}).some((name) => name.toLowerCase() === 'content-type'))
        return `${label} must omit Content-Type for multipart; curl supplies the boundary.`;
    }
  }
  if (!plan.steps.some((step) => step.expect?.body_contains))
    return 'At least one request step must assert a concrete impact status and body substring.';
  return undefined;
}

/** Exported plans must not carry literal operator authentication from a test session. */
export function hasLiteralReplayAuthentication(plan: HttpReplayPlan): boolean {
  return [...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])].some((step) =>
    Object.entries(step.headers ?? {}).some(
      ([name, value]) =>
        /authorization|cookie|token|session|secret|api.?key/i.test(name) && !/\$\{[A-Za-z][A-Za-z0-9_]*\}/.test(value),
    ),
  );
}

/** Inspect literal values, not JSON field names or endpoint path segments. */
export function containsReplaySecret(plan: HttpReplayPlan, secrets: readonly string[]): boolean {
  const values: string[] = [];
  const visit = (value: unknown): void => {
    if (typeof value === 'string') values.push(value.replace(/\$\{[A-Za-z][A-Za-z0-9_]*\}/g, ''));
    else if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === 'object') Object.values(value).forEach(visit);
  };
  for (const step of [...(plan.setup ?? []), ...plan.steps, ...(plan.cleanup ?? [])]) {
    visit(step.headers);
    visit(step.body_json);
    visit(step.multipart);
    visit(step.expect?.body_contains);
    if (step.body) {
      try {
        visit(JSON.parse(step.body));
      } catch {
        if (step.body.includes('=')) for (const value of new URLSearchParams(step.body).values()) visit(value);
        else visit(step.body);
      }
    }
    const query = step.url.split('?')[1];
    if (query) for (const value of new URLSearchParams(query).values()) visit(value);
  }
  return values.some((value) =>
    secrets.some((secret) => {
      if (!secret) return false;
      if (secret.length >= 4) return value.includes(secret);
      const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(?:^|[^a-z0-9_])${escaped}(?:$|[^a-z0-9_])`, 'i').test(value);
    }),
  );
}

export function hasVerifiedReplay(entry: {
  http_replay?: HttpReplayPlan | null;
  http_replay_verification?: HttpReplayVerification;
}): boolean {
  const proof = entry.http_replay_verification;
  return (
    !!entry.http_replay &&
    Value.Check(HttpReplaySchema, entry.http_replay) &&
    !!proof &&
    proof.plan_sha256 === replayPlanDigest(entry.http_replay) &&
    Number.isInteger(proof.request_count) &&
    Number.isInteger(proof.assertion_count) &&
    proof.request_count > 0 &&
    proof.assertion_count > 0 &&
    entry.http_replay.steps.some((step) => !!step.expect?.body_contains)
  );
}

// No shell evaluation, user scripts, local file uploads, or arbitrary curl options are accepted.
export const HTTP_REPLAY_PYTHON = String.raw`
import json, os, pathlib, re, subprocess, sys, base64
from datetime import datetime, timezone

VARIABLES = ("BASE_URL", "BEARER_TOKEN", "COOKIE", "USERNAME", "PASSWORD", "OTP")
os.umask(0o077)
def interpolate(value, variables):
    def replace(match):
        name = match.group(1).upper()
        if name not in variables or variables[name] == "":
            raise ValueError("Missing variable: " + name)
        return variables[name]
    return re.sub(r"\$\{([A-Za-z][A-Za-z0-9_]*)\}", replace, value)

def execute_step(step, variables, directory, index):
    prefix = directory / ("%03d" % index)
    url = interpolate(step["url"], variables)
    from urllib.parse import urlsplit
    base = urlsplit(variables["BASE_URL"])
    parsed = urlsplit(url)
    if not step["url"].startswith("\u0024{BASE_URL}") or not re.match(r"^https?://", url) or parsed.scheme not in ("http", "https") or parsed.netloc != base.netloc or parsed.scheme != base.scheme or parsed.username or parsed.password:
        raise ValueError("Request URLs must start with \u0024{BASE_URL} and resolve to HTTP(S)")
    args = ["curl", "--disable", "--silent", "--show-error", "--globoff", "--connect-timeout", "15", "--max-time", "60",
            "--request", step["method"], "--url", url, "--trace", str(prefix) + ".trace",
            "--dump-header", str(prefix) + ".headers", "--output", str(prefix) + ".body", "--write-out", "%{http_code}"]
    headers = dict(step.get("headers", {}))
    if sum(key in step for key in ("body", "body_json", "multipart")) > 1:
        raise ValueError("Choose only one of body, body_json, or multipart")
    def json_values(value):
        if isinstance(value, str): return interpolate(value, variables)
        if isinstance(value, list): return [json_values(item) for item in value]
        if isinstance(value, dict): return {key: json_values(item) for key, item in value.items()}
        return value
    payload = interpolate(step.get("body", ""), variables).encode()
    if "body_json" in step:
        payload = json.dumps(json_values(step["body_json"])).encode()
        if not any(key.lower() == "content-type" for key in headers): headers["Content-Type"] = "application/json"
    for key, value in headers.items():
        value = interpolate(value, variables)
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_|~-]+", key) or "\r" in value or "\n" in value:
            raise ValueError("Invalid header name or newline in header value")
        # curl's Header; syntax transmits an explicitly empty header. Header:
        # has different semantics for custom headers and can remove it entirely.
        args += ["--header", key + (";" if value == "" else ": " + value)]
    if "multipart" in step:
        parts = step["multipart"]
        if not parts or sum("filename" in part for part in parts) > 1:
            raise ValueError("Multipart replay requires parts and at most one file part")
        payload = b""
        for part in parts:
            name = part["name"]
            value = interpolate(part["value"], variables)
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                raise ValueError("Invalid multipart field name")
            if "filename" in part:
                filename = part["filename"]
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", filename):
                    raise ValueError("Invalid multipart filename")
                content_type = part.get("content_type", "application/octet-stream")
                if not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", content_type):
                    raise ValueError("Invalid multipart content type")
                payload = value.encode()
                args += ["--form", name + "=@-;filename=" + filename + ";type=" + content_type]
            else:
                args += ["--form-string", name + "=" + value]
    elif "body" in step or "body_json" in step:
        # stdin prevents curl's @file syntax from reading operator files.
        args += ["--data-binary", "@-"]
    if step["method"] == "HEAD": args += ["--head"]
    if step.get("follow_redirects"): raise ValueError("Redirects are not supported by HTTP replay")
    if step.get("insecure"): args += ["--insecure"]
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=70)
    pathlib.Path(str(prefix) + ".meta.json").write_text(json.dumps({"exit_code": result.returncode, "captured_at": datetime.now(timezone.utc).isoformat(), "curl_arguments": args[1:], "cwd": os.getcwd(), "stdin_base64": base64.b64encode(payload).decode()}))
    if result.returncode:
        raise ValueError("curl failed (exit %d)" % result.returncode)
    status = int(result.stdout.decode())
    body = pathlib.Path(str(prefix) + ".body").read_bytes()
    expected = step.get("expect")
    if expected:
        needle = interpolate(expected["body_contains"], variables).encode()
        if not needle or status != expected["status"] or needle not in body:
            raise ValueError("HTTP impact assertion failed (status %d)" % status)
    elif status >= 400:
        raise ValueError("Unexpected HTTP failure (status %d)" % status)
    for name, pointer in step.get("save_json", {}).items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in VARIABLES:
            raise ValueError("Extracted variables must have uppercase names distinct from operator variables")
        data = json.loads(body)
        for part in pointer.split("."):
            data = data[int(part)] if isinstance(data, list) else data[part]
        if not isinstance(data, (str, int, float)) or isinstance(data, bool):
            raise ValueError("Extracted variables must be scalar strings or numbers")
        variables[name] = str(data)
    for name, header in step.get("save_headers", {}).items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in VARIABLES:
            raise ValueError("Extracted variables must have uppercase names distinct from operator variables")
        values = []
        for line in pathlib.Path(str(prefix) + ".headers").read_text(errors="replace").splitlines():
            key, separator, value = line.partition(":")
            if separator and key.lower() == header.lower(): values.append(value.strip())
        if not values: raise ValueError("Response header was not found: " + header)
        variables[name] = values[-1]
    return bool(expected)

def run_entry(entry, root):
    directory = root / entry["finding_id"]
    directory.mkdir(parents=True, exist_ok=False)
    variables = {name: os.environ.get(name, "") for name in VARIABLES}
    variables.update(json.loads(os.environ.get("SHANNON_REPLAY_VARIABLES", "{}")))
    if not variables["BASE_URL"]: variables["BASE_URL"] = entry["base_url"]
    plan = entry["plan"]
    requests = assertions = 0
    error = None
    try:
        if not any(step.get("expect", {}).get("body_contains") for step in plan["steps"]):
            raise ValueError("At least one impact assertion is required")
        for step in plan.get("setup", []):
            requests += 1
            execute_step(step, variables, directory, requests)
        for step in plan["steps"]:
            requests += 1
            assertions += int(execute_step(step, variables, directory, requests))
    except Exception as exc:
        error = str(exc)
    finally:
        for step in plan.get("cleanup", []):
            try:
                requests += 1
                execute_step(step, variables, directory, requests)
            except Exception as exc:
                cleanup_error = "Cleanup failed: " + str(exc)
                error = cleanup_error if error is None else error + "; " + cleanup_error
    passed = error is None and assertions > 0
    receipt = {"passed": passed, "request_count": requests, "assertion_count": assertions, "error": error}
    (directory / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(entry["finding_id"] + (": passed" if passed else ": failed - " + str(error)), flush=True)
    return passed

def run(entries):
    root = pathlib.Path(os.environ["OUTPUT_DIR"]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    results = [run_entry(entry, root) for entry in entries]
    return 0 if results and all(results) else 1
`;

export async function verifyHttpReplay(args: {
  findingId: string;
  plan: HttpReplayPlan;
  variables: Record<string, string>;
  deliverablesDir: string;
  targetUrl: string;
  secrets?: readonly string[];
}): Promise<{ verification?: HttpReplayVerification; error?: string; evidence?: HttpEvidenceReceipt[] }> {
  if (replayPlanError(args.plan) !== undefined || !/^(INJ|XSS|AUTH|AUTHZ|SSRF|MISC)-\d{2,}$/.test(args.findingId)) {
    return { error: 'Invalid HTTP replay plan or finding ID.' };
  }
  const runDir = path.join(args.deliverablesDir, 'http-replay-verifications', `${Date.now()}-${randomUUID()}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const baseUrl = new URL(args.targetUrl).origin;
  const entries = [{ finding_id: args.findingId, base_url: baseUrl, plan: args.plan }];
  const source = `${HTTP_REPLAY_PYTHON}\nsys.exit(run(json.loads(base64.b64decode('${Buffer.from(JSON.stringify(entries)).toString('base64')}'))))\n`;
  const environment: NodeJS.ProcessEnv = { ...process.env, OUTPUT_DIR: runDir };
  for (const name of REPLAY_VARIABLES) environment[name] = name === 'BASE_URL' ? baseUrl : (args.variables[name] ?? '');
  environment.SHANNON_REPLAY_VARIABLES = JSON.stringify({ ...args.variables, BASE_URL: baseUrl });
  let code: number;
  try {
    code = await new Promise<number>((resolve, reject) => {
      const child = spawn('python3', ['-c', source], { env: environment, stdio: ['ignore', 'ignore', 'ignore'] });
      const timer = setTimeout(() => child.kill('SIGKILL'), 10 * 60 * 1000);
      child.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.once('close', (exitCode) => {
        clearTimeout(timer);
        resolve(exitCode ?? 1);
      });
    });
  } catch {
    return { error: 'The HTTP verifier could not start Python/curl.' };
  }
  const captureDir = path.join(args.deliverablesDir, 'http-exchanges', args.findingId);
  await mkdir(captureDir, { recursive: true, mode: 0o700 });
  const resultsDir = path.join(runDir, args.findingId);
  let files: string[];
  try {
    files = await readdir(resultsDir);
  } catch {
    return { error: 'HTTP verification did not produce a result.' };
  }
  const traceFiles = files.filter((name) => name.endsWith('.trace')).sort();
  const evidence: HttpEvidenceReceipt[] = [];
  let completeTraces = 0;
  for (const file of traceFiles) {
    const trace = await readFile(path.join(resultsDir, file), 'utf8');
    let metadata: {
      exit_code: number;
      captured_at: string;
      curl_arguments?: string[];
      cwd?: string;
      stdin_base64?: string;
    } = { exit_code: -1, captured_at: new Date().toISOString() };
    try {
      metadata = JSON.parse(
        await readFile(path.join(resultsDir, file.replace(/\.trace$/, '.meta.json')), 'utf8'),
      ) as typeof metadata;
    } catch {
      /* A killed transfer still keeps its partial trace without inventing a curl exit code. */
    }
    const captured = await persistCapturedTrace({
      deliverablesDir: args.deliverablesDir,
      findingId: args.findingId,
      trace,
      exitCode: metadata.exit_code,
      capturedAt: metadata.captured_at,
      ...(metadata.curl_arguments
        ? {
            invocation: await snapshotCurlInvocation(
              metadata.curl_arguments,
              metadata.cwd ?? process.cwd(),
              70,
              args.secrets,
              Buffer.from(metadata.stdin_base64 ?? '', 'base64'),
            ),
          }
        : {}),
    });
    evidence.push(captured);
    if (captured.complete) completeTraces++;
  }
  try {
    const receipt = JSON.parse(await readFile(path.join(resultsDir, 'result.json'), 'utf8')) as {
      passed: boolean;
      request_count: number;
      assertion_count: number;
      error?: string;
    };
    if (code !== 0 || !receipt.passed || receipt.assertion_count < 1)
      return { error: receipt.error ?? 'Replay or cleanup failed.', evidence };
    if (traceFiles.length !== receipt.request_count || completeTraces !== receipt.request_count) {
      return {
        error: 'HTTP verification requires a complete captured request/response for each executed step.',
        evidence,
      };
    }
    return {
      evidence,
      verification: {
        plan_sha256: replayPlanDigest(args.plan),
        verified_at: new Date().toISOString(),
        request_count: receipt.request_count,
        assertion_count: receipt.assertion_count,
      },
    };
  } catch {
    return { error: 'HTTP verification did not finish.', evidence };
  }
}
