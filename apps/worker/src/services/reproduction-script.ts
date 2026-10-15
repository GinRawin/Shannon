// Standalone, selection-based manual reproduction from receipt-backed invocations.

import { randomUUID } from 'node:crypto';
import { chmod, mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { REPRODUCTION_SCRIPT_FILENAME } from '../paths.js';
import { type HttpEvidenceReceipt, readVerifiedHttpEvidence } from './capture-http-request.js';
import { curlArguments } from './curl-invocation.js';
import {
  HTTP_REPLAY_PYTHON,
  type HttpReplayPlan,
  type HttpReplayVerification,
  hasLiteralReplayAuthentication,
  hasVerifiedReplay,
} from './http-replay.js';

interface ReproductionEntry {
  vulnerability_id?: string;
  title?: string;
  status?: string;
  verification_method?: string;
  http_evidence_display?: string;
  http_evidence_reason?: string;
  http_evidence_ids?: string[];
  reproduction_capture_ids?: string[];
  http_evidence_receipts?: HttpEvidenceReceipt[];
  exploitation_steps?: string[];
  proof_of_impact?: string;
  http_replay?: HttpReplayPlan | null;
  http_replay_verification?: HttpReplayVerification;
}

export async function writeManualReproductionScript(
  dir: string,
  entries: readonly ReproductionEntry[],
  targetUrl: string,
  included: ReadonlySet<string>,
): Promise<string> {
  const retained = entries
    .filter(
      (entry): entry is ReproductionEntry & { vulnerability_id: string } =>
        entry.status === 'exploited' &&
        typeof entry.vulnerability_id === 'string' &&
        included.has(entry.vulnerability_id),
    )
    .sort((a, b) => a.vulnerability_id.localeCompare(b.vulnerability_id));
  const recipes = [];
  for (const entry of retained) {
    const commands: Array<Record<string, unknown>> = [],
      secrets: string[] = [];
    const ids =
      entry.reproduction_capture_ids ??
      (entry.http_evidence_display === 'include' ? (entry.http_evidence_ids ?? []) : []);
    for (const id of ids) {
      const receipt = entry.http_evidence_receipts?.find((item) => item.capture_id === id);
      if (!receipt) throw new Error(`Missing reproduction receipt for ${entry.vulnerability_id}: ${id}`);
      const record = await readVerifiedHttpEvidence(dir, receipt);
      if (!record.invocation) {
        commands.push({
          capture_id: id,
          manual_reasons: [
            'Original argv was not recorded. Review the original logs; no command has been inferred from the HTTP trace.',
          ],
        });
        continue;
      }
      const invocation = record.invocation;
      const commandPrefix: string = `${entry.vulnerability_id.replaceAll('-', '_')}_COMMAND_${commands.length + 1}`;
      const parsed = curlArguments(invocation.argv).arguments;
      const argv: Array<string | { variable: string; prefix: string }> = [...invocation.argv];
      for (const [index, variable] of Object.entries(invocation.variables)) {
        const arg = parsed.find((item) => item.index === Number(index));
        if (!arg) throw new Error('Invalid capture variable binding');
        secrets.push(arg.value ?? '');
        if (arg.option === 'header')
          secrets.push((arg.value ?? '').replace(/^[^:]+:\s*/, '').replace(/^Bearer\s+/i, ''));
        argv[Number(index)] = { variable: `${commandPrefix}_${variable}`, prefix: arg.prefix };
      }
      secrets.push(...(invocation.secret_values ?? []));
      commands.push({
        capture_id: id,
        argv,
        cwd: invocation.cwd,
        timeout_seconds: invocation.timeout_seconds,
        arguments: parsed.map(({ option, index, prefix }) => ({ option, index, prefix })),
        inputs: invocation.inputs.map((input) => ({
          ...input,
          ...(input.variable ? { variable: `${commandPrefix}_${input.variable}` } : {}),
        })),
        ...(invocation.stdin_base64 !== undefined ? { stdin_base64: invocation.stdin_base64 } : {}),
        ...(invocation.stdin_variable ? { stdin_variable: `${commandPrefix}_${invocation.stdin_variable}` } : {}),
        manual_reasons: invocation.manual_reasons,
      });
    }
    const redact = (value: string) => {
      for (const secret of [...new Set(secrets)].filter(Boolean).sort((a, b) => b.length - a.length))
        value = value.split(secret).join('[authentication value]');
      return value
        .replace(/\bAT-\d+-[A-Za-z0-9_-]+\b/g, '[access token]')
        .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[JWT]');
    };
    const verified =
      hasVerifiedReplay(entry) && entry.http_replay && !hasLiteralReplayAuthentication(entry.http_replay);
    recipes.push({
      finding_id: entry.vulnerability_id,
      title: redact(entry.title ?? ''),
      method: entry.verification_method ?? 'legacy/manual',
      reason: redact(entry.http_evidence_reason ?? 'Legacy evidence selection has not been reviewed.'),
      steps: (entry.exploitation_steps ?? []).map(redact),
      commands,
      // A verified structured plan is optional and executes ONLY under --verify ID.
      verified: verified
        ? { finding_id: entry.vulnerability_id, base_url: new URL(targetUrl).origin, plan: entry.http_replay }
        : null,
    });
  }
  const json = JSON.stringify(recipes);
  // Base64 avoids Python/JS escape differences and prevents payloads from ending the heredoc.
  const source = `${HTTP_REPLAY_PYTHON}\n${MANUAL_REPRODUCTION_PYTHON}\nmanual_main(json.loads(base64.b64decode('${Buffer.from(json).toString('base64')}')))\n`;
  const script = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    'umask 077',
    '# Requires Bash, Python 3 and curl. No requests are sent without an explicit selection.',
    ...retained.map((entry) => `# ${entry.vulnerability_id}: ${(entry.title ?? '').replace(/[\r\n]/g, ' ')}`),
    'python3 - "$@" <<\'SHANNON_MANUAL_REPRODUCTION_PY\'',
    source,
    'SHANNON_MANUAL_REPRODUCTION_PY',
    '',
  ].join('\n');
  await mkdir(dir, { recursive: true });
  const scriptPath = path.join(dir, REPRODUCTION_SCRIPT_FILENAME);
  const temporary = `${scriptPath}.tmp-${randomUUID()}`;
  try {
    await writeFile(temporary, script, { mode: 0o700, flag: 'wx' });
    await chmod(temporary, 0o700);
    await rename(temporary, scriptPath);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
  return scriptPath;
}

const MANUAL_REPRODUCTION_PYTHON = String.raw`
import base64, tempfile, urllib.parse, shlex

def required(name):
    value = os.environ.get(name)
    if value is None or value == "": raise ValueError("Missing environment variable: " + name)
    return value

def origin_override(url):
    override = os.environ.get("BASE_URL", "")
    if not override: return url
    parsed, replacement = urllib.parse.urlsplit(url), urllib.parse.urlsplit(override)
    if replacement.scheme not in ("http", "https") or not replacement.netloc or replacement.path not in ("", "/") or replacement.query or replacement.fragment:
        raise ValueError("BASE_URL must be an HTTP(S) origin; original request paths are preserved")
    return urllib.parse.urlunsplit((replacement.scheme, replacement.netloc, parsed.path, parsed.query, parsed.fragment))

def prepare_command(command, directory):
    if command.get("manual_reasons"): raise ValueError("Manual preparation required: " + "; ".join(command["manual_reasons"]))
    argv = [value if isinstance(value, str) else value["prefix"] + required(value["variable"]) for value in command["argv"]]
    inputs = {}
    for index, item in enumerate(command["inputs"]):
        destination = directory / "inputs" / ("%03d" % index) / pathlib.Path(item["path"]).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = pathlib.Path(required(item["variable"])).read_bytes() if item.get("variable") else base64.b64decode(item["base64"])
        destination.write_bytes(data)
        inputs[item["path"]] = str(destination)
    def mapped(filename):
        absolute = str(pathlib.Path(command["cwd"], filename).resolve())
        if absolute not in inputs: raise ValueError("Missing captured input dependency: " + filename)
        return inputs[absolute]
    for arg in command["arguments"]:
        index, option, prefix = arg["index"], arg["option"], arg["prefix"]
        value = argv[index][len(prefix):]
        if option == "url": value = origin_override(value)
        elif option in ("output", "dump-header", "cookie-jar", "trace"):
            if value != "-": value = str(directory / (option + "-" + str(index)))
        elif option in ("cacert", "cert", "key", "upload-file"): value = mapped(value)
        elif option == "cookie" and "=" not in value: value = mapped(value.lstrip("@"))
        elif option == "header" and value.startswith("@"): value = "@" + mapped(value[1:])
        elif option in ("data", "data-binary", "data-urlencode", "json", "write-out") and "@" in value:
            match = re.match(r"^([^=@]*@)(.*)$" if option == "data-urlencode" else r"^(@)(.*)$", value)
            if match and match.group(2) != "-": value = match.group(1) + mapped(match.group(2))
        elif option == "form":
            match = re.match(r"^([^=]+=[@<])([^;]+)(.*)$", value)
            if match: value = match.group(1) + mapped(match.group(2)) + match.group(3)
        argv[index] = prefix + value
    return ["curl", "--disable"] + argv + ["--trace", str(directory / "curl.trace")]

def show_entry(entry):
    print(entry["finding_id"] + ": " + entry["title"] + " [" + entry["method"] + "]")
    print("  Evidence selection: " + entry["reason"])
    for index, step in enumerate(entry["steps"], 1): print("\nStep %d: %s" % (index, step))
    for command in entry["commands"]:
        print("\nCapture " + command["capture_id"])
        if command.get("argv"):
            preview = "curl " + " ".join(shlex.quote(value) if isinstance(value, str) else shlex.quote(value["prefix"]) + '"' + chr(36) + '{' + value["variable"] + ':?}"' for value in command["argv"])
            print("  Recorded command (authentication parameterized; inputs restored when executed):\n  " + preview)
        for reason in command.get("manual_reasons", []): print("  Manual preparation: " + reason)
        for value in command.get("argv", []):
            if isinstance(value, dict): print("  Required environment variable: " + value["variable"] + " (full argument value, without its option prefix)")
        for item in command.get("inputs", []):
            if item.get("variable"): print("  Required input file path: " + item["variable"])
        if command.get("stdin_variable"): print("  Required stdin environment variable: " + command["stdin_variable"])

def manual_main(entries):
    args = sys.argv[1:]
    if not args or args in (["--list"], ["--help"]):
        print("Usage: bash reproduce.sh [FINDING_ID | --show FINDING_ID | --all | --verify FINDING_ID]")
        for entry in entries:
            print(entry["finding_id"] + ": " + entry["title"] + " (" + str(len(entry["commands"])) + " captured commands; " + entry["method"] + ")")
        if not entries: print("No retained findings.")
        return
    by_id = {entry["finding_id"]: entry for entry in entries}
    verify = len(args) == 2 and args[0] == "--verify"
    showing = len(args) == 2 and args[0] == "--show"
    if args == ["--all"]: selected = entries
    elif (len(args) == 1 and args[0] in by_id) or ((verify or showing) and args[1] in by_id): selected = [by_id[args[-1]]]
    else: print("Unknown finding or arguments", file=sys.stderr); sys.exit(2)
    if showing:
        for entry in selected: show_entry(entry)
        return
    # Resolve every required value/input before sending any request in the selected set.
    root = pathlib.Path(os.environ.get("OUTPUT_DIR", "./shannon-replay-results")).resolve()
    root.mkdir(parents=True, exist_ok=True)
    root = pathlib.Path(tempfile.mkdtemp(prefix="run-", dir=root))
    prepared = []
    try:
        if verify:
            if not selected[0].get("verified"): raise ValueError("No host-verified impact assertions for this finding")
        else:
            for entry in selected:
                steps = []
                for index, command in enumerate(entry["commands"]):
                    directory = root / entry["finding_id"] / ("command-%03d" % (index + 1))
                    directory.mkdir(parents=True)
                    stdin = required(command["stdin_variable"]).encode() if command.get("stdin_variable") else base64.b64decode(command.get("stdin_base64", ""))
                    steps.append((command, directory, prepare_command(command, directory), stdin))
                prepared.append((entry, steps))
    except Exception as exc:
        print(str(exc), file=sys.stderr); sys.exit(2)
    print("Results: " + str(root))
    if verify:
        os.environ["OUTPUT_DIR"] = str(root)
        sys.exit(run([selected[0]["verified"]]))
    failed = False
    for entry, steps in prepared:
        show_entry(entry)
        if not steps:
            print("Manual/browser verification required; no HTTP reproduction was performed.")
            (root / (entry["finding_id"] + "-manual.json")).write_text(json.dumps({"status": "manual_required"}))
            continue
        for command, directory, argv, stdin in steps:
            try:
                result = subprocess.run(argv, cwd=directory, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=command["timeout_seconds"])
                (directory / "stdout").write_bytes(result.stdout)
                (directory / "stderr").write_bytes(result.stderr)
                record = {"capture_id": command["capture_id"], "exit_code": result.returncode, "status": "command_completed" if result.returncode == 0 else "command_failed", "impact_assertion": "not_checked"}
                failed = failed or result.returncode != 0
            except Exception as exc:
                record = {"capture_id": command["capture_id"], "status": "command_failed", "error": str(exc), "impact_assertion": "not_checked"}
                failed = True
            (directory / "result.json").write_text(json.dumps(record, indent=2))
            print(command["capture_id"] + ": " + record["status"] + "; vulnerability impact not automatically asserted")
    sys.exit(1 if failed else 0)
`;
