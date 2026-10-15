# HTTP validation evidence

New exploit runs collect the HTTP exchange from the validation invocation itself. This feature does not intercept every tool's network traffic. The agent chooses the validation request; the host executes it, records its trace, and verifies the attachment before publication.

## Agent workflow

1. Call `capture_http_request` with a queue `vulnerability_id` and `curl_arguments` array. Use absolute paths for files, or paths relative to the assessed repository. The tool runs curl directly; `$TOKEN`, command substitution, pipes, and redirections are not expanded by a shell. Curl config files and custom trace settings are rejected. Curl's implicit configuration file is disabled so it cannot override capture settings.
2. Inspect the returned stdout/stderr and actual on-disk evidence to assess the result. A successful tool invocation or `complete: true` means the request/response was captured, not that exploitation succeeded. Check `exit_code` and the actual response. Output to the model is bounded to 32 KiB per stream; the trace retains the full captured contents.
3. Submit the relevant capture IDs in `add_exploit.http_evidence_ids`. `list_http_evidence` retrieves existing receipts without sending requests. IDs must come from this collector's real tool calls and belong to the submitted queue ID. A child can call the same evidence tools and return its IDs to the parent.
4. For browser/DOM proof without an applicable complete HTTP exchange, submit `http_evidence_unavailable_reason` along with the original browser proof. The final report discloses this limitation. Never repeat a one-time or state-changing proof solely to obtain HTTP evidence.

Example tool arguments:

```json
{
  "vulnerability_id": "AUTHZ-01",
  "curl_arguments": ["-sS", "-H", "Cookie: session=actual-test-session", "https://target.example/api/private"],
  "timeout_seconds": 120
}
```

The tool returns a `capture_id`, `file`, `sha256`, timestamp, curl exit code, completeness flag, and curl output. HTTP errors such as 401 are captured too; they are evidence of that response, not evidence of successful exploitation. Transport failures/timeouts retain incomplete evidence and cannot silently count as complete HTTP proof.

`verify_http_replay` is an optional separate facility for checking a structured, repeatable HTTP PoC with explicit impact assertions and cleanup. Its real exchanges also produce usable capture IDs. Do not invoke it merely to replace missing original evidence in a non-repeatable flow.

## Storage and report assembly

Private records live at:

```text
.shannon/deliverables/http-exchanges/<original-queue-id>/exchange-<timestamp>-<capture-id>.json
```

Each record includes the original curl trace and decoded request/response bytes as Base64. Text and binary bodies, authentication headers, cookies, redirects, and failed transfers remain in the private evidence. These are application-level curl traces, not PCAP or exact TCP/TLS frames.

Host-only receipts are written into the structured exploit collector; the model cannot submit its own receipt. The host checks the stored bytes against the receipt at submission and report assembly. Finding renumbering preserves original queue IDs inside receipts. The report attaches only selected receipt-backed captures for new enforced entries, rather than every file in the directory. Changes to a selected file fail verification. This checks consistency with the host's recorded execution; it is not a signed, tamper-proof forensic archive.

Report projections redact configured login credentials while leaving private evidence unchanged. A complete HTTP attachment does not automatically imply a host-verified impact assertion or inclusion in `reproduce.sh`.

In Markdown and PDF, captured requests and responses appear once immediately after Exploitation Steps, under “捕获的 HTTP 请求与响应”. The report writer does not collect a separate model-authored evidence field. Legacy narrative evidence is ignored by the final renderers, and findings without HTTP captures explicitly state that no associated HTTP capture is available. No substitute evidence is generated.

The `shannon-curl` CLI uses the same capture implementation and remains useful for manual operation. For new exploit submissions use the structured tools, which additionally register host receipts. Legacy runs without receipt fields retain their existing report-loading behavior.

## Deployment and verification

Rebuild the worker image before the next assessment (`./shannon build` for local development). Source changes alone do not update an existing worker image. There are no new proxy services, network permissions, or changes to an already running assessment. The extra instructions are injected by the new executor; live-mounted prompt files need not be changed.

Run `node scripts/verify-http-evidence.mjs` for loopback-only integration checks, including single-send validation, provenance and checksum enforcement, failure handling, renumbering, and report attachment. The test builds into a temporary directory and does not contact assessment targets.
