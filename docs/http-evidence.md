# Evidence selection and manual reproduction

## Exploit agent decisions

Every newly confirmed finding must submit `verification_method` (`http`, `browser`, `mixed`, `other`), `http_evidence_display` (`include`, `omit`), and a meaningful `http_evidence_reason` to `add_exploit`. The exploit agent decides whether HTTP exchanges help demonstrate this finding. The report agent cannot override that decision.

For `include`, select actual capture IDs in `http_evidence_ids`. Only those records appear in Markdown/PDF. For `omit`, leave that list empty and preserve actual browser/other observations in `proof_of_impact`; optionally supply existing workspace-relative screenshots/logs in `browser_evidence_files`. No HTTP capture or empty/missing-HTTP section is required for browser-only XSS. Do not put auxiliary HTTP transcripts into proof intended for browser-only presentation. The host validates referenced files, capture ownership, completeness and SHA-256, but does not claim to independently assess the vulnerability from transport success.

The host projects original browser/other observations into a verification section, including fenced DOM/console results. Renumbering and compaction preserve evidence bytes and receipt identities. Existing entries without an explicit display decision are `unreviewed`: available directory files are never silently attached. Review and migrate them explicitly instead.

## Capture and provenance

Use either `shannon-curl --finding-id AUTHZ-01 -- <curl arguments>` or `capture_http_request` with `vulnerability_id` and `curl_arguments`. In an active worker both invoke the same live collector through its host capture service; CLI receipts are visible in `list_http_evidence` and accepted by `add_exploit`. CLI arguments undergo shell expansion in the caller; structured argv is literal. CLI tool output is bounded to the same 32 KiB per stream as structured tool output. Full HTTP bytes remain on disk. A failed host call never falls back to a second request.

The validation and capture are a single invocation. Never repeat state-changing, one-time, or browser proofs merely to obtain a capture or script. `list_http_evidence` is read-only. Child agents inherit the same capture tools and CLI service. A standalone CLI outside an active worker can still capture privately, but its files are not automatically imported as host receipts.

Private records live in `.shannon/deliverables/http-exchanges/<original-queue-id>/`. Version 3 records retain original curl argv, cwd, timeout, input snapshots, trace, exact decoded bytes, and export variable bindings. Receipts bind all of these bytes by SHA-256; the model cannot provide its own receipts. Configuration files, independent/parallel transfers and trace overrides are rejected. These are curl application-level exchanges, not TCP/TLS PCAP. Consistency with a host receipt is not a signed forensic archive.

Supported file inputs include curl data/JSON, multipart, upload, cookie/header files and certificates. Regular inputs are snapshotted up to 16 MiB; credential-bearing files require a fresh operator-provided path in the exported script. Unfamiliar options, unrecorded stdin, complex multipart file lists, missing inputs and historical dependencies are explicitly manual-only. They are not silently omitted from an executable recipe.

## reproduce.sh

`reproduction_capture_ids` independently chooses actual recorded calls in execution order, including required setup and cleanup. By default it uses the displayed HTTP IDs; `[]` records manual/browser steps only. HTTP display can be omitted while explicitly retaining auxiliary calls for manual reproduction. All retained exploited findings appear in the script index.

Script generation does not require `verify_http_replay` and sends no requests. Exploit-mode finalization generates the script from committed collectors and retained report IDs; report-only retries restore it. Publication copies it with mode 0700. Generation failure fails finalization; PDF rendering remains warning-only.

```bash
bash reproduce.sh                    # list findings; sends nothing
bash reproduce.sh --show XSS-01      # show manual steps/commands and required variables
bash reproduce.sh AUTHZ-01           # execute only this finding, or show browser/manual steps
bash reproduce.sh --all             # explicitly execute all packaged calls
bash reproduce.sh --verify AUTHZ-01  # explicitly run optional host-verified impact assertions
```

Authentication stays in private evidence. The exported script requires environment variables for sensitive argument values or paths to credential-bearing input files. `--show` lists their exact names and meanings. Sensitive JSON/form bodies are supplied as entire argument values so quoting, JSON keys and payload bytes are not rewritten. Missing required values/dependencies are detected before sending any selected raw commands. Input snapshots are restored in a fresh results directory; output/cookie-jar/trace paths are redirected there. Each command saves stdout, stderr, a trace and a result. Command success is reported separately from impact assertion success; a browser-only operation is reported as manual verification, never as an HTTP reproduction pass.

Ordinary calls use the original URL, including its path and query. Optional `BASE_URL` must be an HTTP(S) origin and replaces only the origin. Structured verifier plans use the assessment origin by default as well. Authentication and request/response projections for the report retain the configured-login redaction behavior.

`verify_http_replay` remains an optional facility for repeatable plans with explicit impact assertions and cleanup. It sends real requests. Submit an identical successfully verified plan as `http_replay`; export never treats an unverified plan or old arbitrary Bash as host-verified. Literal authentication headers in plans are rejected; use operator/extracted variables. It is not a prerequisite for recording manual reproduction.

## Historical repair and deployment

`dist/scripts/repair-evidence-report.js --source <original-deliverables> --report <original-report.json> --output <new-directory> --decisions <reviewed-decisions.json>` creates a separate offline correction. It requires a reviewed decision for every retained finding, imports only selected historical captures with original-file hashes, preserves original observations and refuses to overwrite existing output. Recovered commands require original log references/checksums; missing original argv or input snapshots stays manual-only. The repair does not call curl, a browser or a scanner. `--no-pdf` permits local checks when Typst is unavailable.

Rebuild the worker image (`./shannon build`) before a new assessment. Existing containers continue using their installed code. Run `node scripts/verify-http-evidence.mjs` for loopback-only integration checks covering capture, provenance, evidence choice, browser rendering, manual reproduction, authentication, dependencies, CLI registration and report recovery.
