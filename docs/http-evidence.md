# Evidence selection and reproducible verification

## Exploit plan and Record verification

The Exploit agent submits `http_replay` with the exact HTTP proof steps and explicit status/body assertions to `add_exploit`. Submission records the agent's claim; it does not grant host verification or send another request. Browser-dependent proof still requires a replay plan so Record can capture the associated HTTP packet.

Record executes the saved plan with `verify_http_replay` and owns the resulting capture receipts. A `verified` verdict requires a passing host replay and every complete packet from that replay. A diagnostic capture alone cannot grant verified status. Failed assertions are recorded as `failed`, reviewed by the corresponding exploit capability, and retried once. XSS also requires fresh JavaScript execution evidence.

Each Record stage permits at most three HTTP replay attempts per finding, including the first, and two variable corrections. Exhaustion produces a host-retained failure even without an agent verdict. Original exploit log paths and per-attempt diagnostics are passed to the fresh review and retry sessions. Retry updates use original IDs in source collectors and mapped IDs only in renumbered collectors.

After the single review/retry round, unresolved findings remain in their original collectors and failure audit; they are not relabeled as false positives. `record_report_exclusions.json` records their original/report IDs, source collector and exclusion reasons. The report allowlist and recorded report inputs retain only verified findings with complete associated packets (and JavaScript execution evidence for XSS). An unresolved finding does not prevent publication of the other verified findings.

The host attaches only selected Record evidence, checking ownership, completeness and SHA-256. Both renumbered initial collectors and expansion collectors use report IDs. Report admission uses these IDs directly and reverses the committed mapping to locate original task captures; it never applies the forward mapping again. Expansion identity mappings come from committed candidate queues. Renumbering and compaction preserve evidence bytes and receipt identities. Available directory files are never silently attached.

## Capture and provenance

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

Rebuild the worker image (`./shannon build`) before a new assessment. Existing containers continue using their installed code. Run `node scripts/verify-http-evidence.mjs` for loopback-only integration checks covering capture, Record verdicts, provenance, report admission, manual reproduction, authentication, dependencies and report recovery. Run `node scripts/test-report-admission.mjs` for offline regressions covering overlapping task/report IDs, expansion admission and evidence ownership after compaction.
