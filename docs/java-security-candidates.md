# Java source/sink candidate retriever (`find_security_candidates`)

`find_security_candidates` is a **read-only navigation aid** for the Pre-Recon and Recon agents. It
uses a curated Java source/sink rule set plus a lightweight Tree-sitter AST scan to return *possible*
source, sink, transform, and security-boundary locations as `xx.java:line`. The agent still performs
the source reading, path tracing, and vulnerability judgement itself.

The tool returns locations and evidence only. It never claims a confirmed vulnerability, never runs a
full data-flow/taint analysis, never compiles or runs the target, and never downloads rules at scan
time. It is registered only for the `pre-recon` and `recon` stages — no workflow phase, deliverable,
or Explore AST v3 code is changed.

## Contract

Input:

```ts
{
  vulnerability_type: 'injection' | 'xss' | 'ssrf' | 'auth' | 'authz'; // required
  limit: number;                          // required, 1..100
  function_name?: string;                 // optional, <= 256 chars; literal only, no regex
  cursor?: string;                        // optional, opaque next-page cursor
}
```

Output: `status` (`complete | partial | unavailable | invalid_cursor`), the returned `candidates`,
`next_cursor`, `has_more`, `snapshot_id`, `stats`, and `warnings`. Each candidate carries `role`,
`vulnerability_types`, `category`, `file` (source-root-relative POSIX path), `line`, `column`,
`containing_symbol`, `function`, `resolved_api`, `confidence`, `code`, `constant_state`, `reason`,
and `rule_ids`.

### Function-name search

- No `function_name`: recall by vulnerability type from the rule set.
- Full API (`java.sql.Statement.executeQuery`): the receiver type is resolved when possible.
- Simple name (`executeQuery`): enumerates same-named calls. A call whose receiver type is resolved to
  the rule class is a classified match; a call whose receiver type is unproven is returned as
  `role: "unclassified"`, `confidence: "name_only"`.
- A project method absent from the dictionary (e.g. `executeSql`) is returned as `unclassified`.
- Language-specific API names are never auto-aliased (there is no `sprintf` → `String.format` bridge).

### Confidence tiers

`exact_signature` > `structural` > `type_inferred` > `name_only`. A same-named call is never promoted
to a well-known API: with only a method name and no type evidence it stays `name_only` (and is
`unclassified` during a function-name search).

## Conservative constant filtering

Filtering only ever *removes* a candidate that the rule itself permits removing, and only when the
sensitive input is provably constant. Evaluation folds literals, simple single-assignment locals, local
string concatenation, and constant `String.format`/`Formatter.format` results. Parameters, fields,
calls, branches, aliases, reflection, and cross-procedural values are `dynamic`/`unknown` and the
candidate is retained. Rules use `never`, `proven_constant_only`, or `format_aware` (`String.format`
with a constant format string that references no dynamic argument). `name_only` candidates are never
constant-filtered.

Examples that are retained: `stmt.executeQuery("..." + id)`, `request.getParameter("id")`,
`new ProcessBuilder("ping", host).start()`, `Runtime.getRuntime().exec(new String[]{"ping", host})`,
`out.write(userInput)`, `hasRole("ADMIN")`, `String.format("%s", userInput)`. Examples that are
filtered: `stmt.executeQuery("SELECT * FROM users")`, `out.write("<h1>Hello</h1>")`,
`String.format("123", userInput)`.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `SHANNON_SECURITY_CANDIDATES_ENABLED` | `true` | When `false`, the tool is not registered and no index is built. |
| `SHANNON_SECURITY_CANDIDATES_TIMEOUT_MS` | `30000` | Time budget for the file scan and for the AST index. |
| `SHANNON_SECURITY_CANDIDATES_MAX_FILE_BYTES` | `1048576` | Files larger than this are skipped and counted. |
| `SHANNON_SECURITY_CANDIDATES_MAX_FILES` | `20000` | Upper bound on scanned files. |
| `SHANNON_SECURITY_CANDIDATES_MAX_RESULTS` | `100` | Upper bound on `limit`. |

With the feature disabled, behavior is identical to before the change: no tool, no index, no cache.

## Caching

The index is written under `<target>/.shannon/cache/security-candidates/v1/` (`index.json` +
`manifest.json`). The `snapshotId` binds the per-file content SHA-256 manifest, the rule version hash,
the scan parameters, and the index schema version — not Git HEAD alone, so uncommitted edits and rule
upgrades both invalidate it. Within one process, concurrent Pre-Recon/Recon calls share a single build
(single-flight). Across processes, a fresh process re-hashes files and reuses the parsed index from
disk. Builds are idempotent, so the best-effort cross-process lock is only an optimization.

Cursors are opaque and bound to `snapshot_id + rule_version + query + sort_version`; a cursor from a
different snapshot or query returns `invalid_cursor` rather than silently restarting at page one.

## Failure behavior

Infrastructure faults never fail the agent: a missing parser, an unreadable rule file, or a timeout
becomes `partial`/`unavailable` with a structured warning. A malformed rule file is reported, never
treated as an empty (clean) scan. An individual Java file that Tree-sitter cannot parse increments
`stats.parse_errors`, is named in `warnings`, and makes the result `partial` so partial coverage is never
reported as a clean `complete` scan.

## Rule set and provenance

The runtime loads `apps/worker/src/services/java-security/data/java-security-rules.json` (schema
version 1). Every rule carries an `origin` (`repository`, `commit`, `file`, `original_rule`,
`license`). The committed rules are curated by this project (`repository: "shannon:curated"`) and
cover Servlet/Spring HTTP sources, JDBC/JPA/Hibernate/JdbcTemplate SQL, `Runtime`/`ProcessBuilder`
commands, `URL`/`HttpClient`/`RestTemplate`/`OkHttp`/Apache HttpClient requests, `File`/`Paths`/
`Files` paths, `PrintWriter`/`JspWriter`/`Model` output, `String.format`, and Spring Security /
Servlet auth, authz, and route boundaries.

### Expanding the rule set (build time, offline)

`apps/worker/src/services/java-security/import/rules-importer.ts` converts the statically convertible
subset of upstream models into the normalized schema; `scripts/import-java-security-rules.mjs` drives
it. It supports CodeQL `.model.yml` `sourceModel`/`sinkModel` rows, Tai-e/SecConfig signature lists,
and Find Security Bugs-style descriptor lists. Composite access paths (`ReturnValue.Element`,
`Argument[this].x`) and non-source/sink predicates are counted as `unsupported` rather than guessed.

```bash
pnpm --filter @shannon/worker build
node scripts/import-java-security-rules.mjs --format codeql \
  --out /tmp/java-security-rules.json --report /tmp/rule-import-report.json \
  --base apps/worker/src/services/java-security/data/java-security-rules.json \
  /path/to/codeql-java-model.yml
```

Before committing imported rules, lock the upstream commit and confirm its license permits
redistribution (this is a merge gate); only reviewed, redistributable rule text may be committed.

## Coverage and known gaps

- **Java only.** Non-Java projects return an empty, `complete` result and the agent falls back to the
  normal analysis flow.
- **MyBatis mapper XML is not scanned in this revision.** XML `${...}` sinks are explicitly reported
  as a gap in `warnings`; the tool does not claim full Java SQL sink coverage.
- **No cross-procedure/trace analysis.** Only per-call positions are reported.
- **Heuristic type resolution.** Receiver types come from imports, local/parameter/field declarations,
  constructors, and a `java.lang` fallback; unresolvable receivers degrade to `name_only`.
- **Rule recall depends on the rule set**, not on a complete framework model. Absence of a candidate
  is not proof of absence.

## Tests

```bash
pnpm --filter @shannon/worker build
node scripts/test-java-security-candidates.mjs
node scripts/test-java-security-importer.mjs
```

The candidate test copies `scripts/fixtures/java-security/repo` into a temporary directory and asserts
the §6.4/§11.1/§11.2 acceptance cases (SQL/command/XSS/SSRF/auth/authz retention and filtering,
function-name classified vs unclassified, deterministic pagination, invalid cursor, concurrent
single-flight, non-Java fallback, disable switch).
