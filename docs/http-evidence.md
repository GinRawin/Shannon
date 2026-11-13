# Evidence selection and reproducible verification

## Exploit plan and Record verification

The Exploit agent submits `http_replay` with the exact HTTP proof steps and explicit status/body assertions to `add_exploit`. Submission records the agent's claim; it does not grant host verification or send another request. Browser-dependent proof still requires a replay plan so Record can capture the associated HTTP packet.

Record executes the saved plan with `verify_http_replay` and owns the resulting capture receipts. A `verified` verdict requires a passing host replay and every complete packet from that replay. A diagnostic capture alone cannot grant verified status. Failed assertions are recorded as `failed`, reviewed by the corresponding exploit capability, and retried once. XSS also requires `browser_replay`: `verify_http_replay` executes the saved UI steps in a fresh host Chromium browser after HTTP replay passes. It substitutes an unpredictable `${XSS_MARKER}` and requires an exact matching JavaScript dialog, then saves a screenshot and hashed receipt in `browser-replay-verifications/<source-ID>/<attempt-UUID>/`. The receipt binds the finding, stage, plan digest, attempt, origin and HTTP capture IDs. Record, retry, resumed report admission and final evidence attachment recheck this provenance. Self-reported title/dialog strings and old screenshots do not grant verification. Browser failure consumes the same bounded attempt as HTTP failure; review supplies `revised_browser_replay` for retries.

Browser plans accept only `goto`, `fill`, `click`, `hover`, `press`, `wait_for` and optional cleanup. No JavaScript evaluation or workspace script is executed by the verifier. Navigation and browser HTTP/WebSocket traffic are restricted to the assessment origin. `use_auth_state` loads only that origin's saved state; other values use the private replay variable handoff. Chromium uses `PLAYWRIGHT_MCP_EXECUTABLE_PATH` when configured (the worker image supplies it), otherwise the installed Playwright Chromium. Missing browser/authentication, timeouts and failed cleanup produce a structured failure.

Each Record stage permits at most three HTTP replay attempts per finding, including the first, and two variable corrections. Exhaustion produces a host-retained failure even without an agent verdict. Original exploit log paths and per-attempt diagnostics are passed to the fresh review and retry sessions. Retry updates use original IDs in source collectors and mapped IDs only in renumbered collectors.

After the single review/retry round, unresolved findings remain in their original collectors and failure audit; they are not relabeled as false positives. `record_report_exclusions.json` records their original/report IDs, source collector and exclusion reasons. The report allowlist and recorded report inputs retain only verified findings with complete associated packets (and JavaScript execution evidence for XSS). An unresolved finding does not prevent publication of the other verified findings.

The host attaches only selected Record evidence, checking ownership, completeness and SHA-256. Both renumbered initial collectors and expansion collectors use report IDs. Report admission uses these IDs directly and reverses the committed mapping to locate original task captures; it never applies the forward mapping again. Expansion identity mappings come from committed candidate queues. Compaction registers a kept expansion reference in the class renumber map and rewrites that reference in the expansion collector, so the reproduction script resolves the compacted report ID. Renumbering and compaction preserve evidence bytes and receipt identities. Available directory files are never silently attached.

## Capture and provenance

Replay variables are resolved only for inputs consumed by the current HTTP or browser plan. HTTP variables produced by earlier `save_json`/`save_headers` steps are resolved inside that attempt; unused private definitions, including expired tokens from an earlier plan, do not block it. Exploit submission validates saved definitions and required names without trying to resolve response-derived values before Record runs. Record reports missing, expired or unresolvable required inputs as structured failures.

For `response_extract`, `refresh: each_attempt` (the default) reads the latest available JSON response each time. `on_ttl_expiry` with `ttl_seconds` may reuse an in-memory value until its source response expires, then extracts again. TTL uses the response's original `captured_at`, so rereading an old response cannot renew a token. Failed transfers are ignored. A missing timestamp with a TTL, a stale source or a failed pointer requires refreshing the source flow; no token is guessed. Definition `updated_at` describes the definition and does not expire newly extracted values. TOTP is generated for the current time on every resolution, including code rollover. Static values retain their saved TTL and require an observed correction when expired because they have no automatic refresh source.

Record provides `capture_http_request` with `finding_id` and `curl_arguments` for capturing a single request separately from structured plan verification. It accepts only the assessment origin, rejects redirects and config files, and supports ordinary combined curl flags such as `-skS`. Structured argv is literal. Tool output is bounded to 32 KiB per stream; full HTTP bytes remain on disk. A failed capture never falls back to a second request. The standalone `shannon-curl` CLI also captures privately, but its files are not automatically trusted as Record receipts.

Plan execution and capture are a single invocation. Exporting a reproduction script sends no requests. Capture ownership belongs to the Record collector that executed the request, so borrowed or invented capture IDs cannot grant a verified verdict.

Private records live in `.shannon/deliverables/http-exchanges/<original-queue-id>/`. Version 3 records retain original curl argv, cwd, timeout, input snapshots, trace, exact decoded bytes, and export variable bindings. Receipts bind all of these bytes by SHA-256; the model cannot provide its own receipts. Configuration files, independent/parallel transfers and trace overrides are rejected. These are curl application-level exchanges, not TCP/TLS PCAP. Consistency with a host receipt is not a signed forensic archive.

Supported file inputs include curl data/JSON, multipart, upload, cookie/header files and certificates. Regular inputs are snapshotted up to 16 MiB; credential-bearing files require a fresh operator-provided path in the exported script. Unfamiliar options, unrecorded stdin, complex multipart file lists, missing inputs and historical dependencies are explicit replay failures. They are not silently omitted from an executable recipe.

## reproduce.sh

`reproduction_capture_ids` independently chooses actual recorded calls in execution order, including required setup and cleanup. By default it uses the displayed HTTP IDs; `[]` records manual/browser steps only. HTTP display can be omitted while explicitly retaining auxiliary calls for manual reproduction. All retained exploited findings appear in the script index.

Script generation does not require `verify_http_replay` and sends no requests. Exploit-mode finalization generates the script from committed collectors and retained report IDs; report-only retries restore it. Publication copies it with mode 0700. Generation failure fails finalization; PDF rendering remains warning-only.

```bash
bash reproduce.sh                    # list findings; sends nothing
bash reproduce.sh --show XSS-01      # show operator steps/commands and required variables
bash reproduce.sh AUTHZ-01           # execute only this finding, or show browser/operator steps
bash reproduce.sh --all             # explicitly execute all packaged calls
bash reproduce.sh --verify AUTHZ-01  # explicitly run optional host-verified impact assertions
```

Authentication stays in private evidence. The exported script requires environment variables for sensitive argument values or paths to credential-bearing input files. `--show` lists their exact names and meanings. Sensitive JSON/form bodies are supplied as entire argument values so quoting, JSON keys and payload bytes are not rewritten. Missing required values/dependencies are detected before sending any selected raw commands. Input snapshots are restored in a fresh results directory; output/cookie-jar/trace paths are redirected there. Each command saves stdout, stderr, a trace and a result. Command success is reported separately from impact assertion success; a browser-only operation remains browser evidence and never counts as an HTTP reproduction pass.

Ordinary calls use the original URL, including its path and query. Optional `BASE_URL` must be an HTTP(S) origin and replaces only the origin. Structured verifier plans use the assessment origin by default as well. Authentication and request/response projections for the report retain the configured-login redaction behavior.

Record's `verify_http_replay` executes the plan saved by Exploit and evaluates explicit impact assertions and cleanup. Literal authentication headers in plans are rejected; use operator/extracted variables. Export never treats an unverified plan or old arbitrary Bash as host-verified. Passing assertions establish only the conditions encoded by the plan; HTTP 200 and a generic response substring alone do not prove a timing or browser-execution impact.

## Historical repair and deployment

`dist/scripts/repair-evidence-report.js --source <original-deliverables> --report <original-report.json> --output <new-directory> --decisions <reviewed-decisions.json>` creates a separate offline correction. It requires a reviewed decision for every retained finding, imports only selected historical captures with original-file hashes, preserves original observations and refuses to overwrite existing output. Recovered commands require original log references/checksums; missing original argv or input snapshots stays manual-only. The repair does not call curl, a browser or a scanner. `--no-pdf` permits local checks when Typst is unavailable.

Rebuild the worker image (`./shannon build`) before a new assessment. Existing containers continue using their installed code. Run `node scripts/verify-http-evidence.mjs` for loopback-only integration checks covering capture, Record verdicts, provenance, report admission, manual reproduction, authentication, dependencies and report recovery. Run `node scripts/test-report-admission.mjs` for offline regressions covering overlapping task/report IDs, expansion admission and evidence ownership after compaction. Run `node scripts/test-replay-variables.mjs` for offline regressions covering variable scoping, TTL/refresh behavior and the Exploit-to-Record handoff.
