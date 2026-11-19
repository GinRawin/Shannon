# Explore Code-Clone Retrieval

The Explore stage turns record-verified sink locations into deterministic Type-2/Type-3 code-clone
candidates. Since v3 the retrieval is **AST-structural** (`ast_structural_clone_v1`, schema v3): the
recorded line is mapped to a Tree-sitter anchor, expanded into a Sink-anchored AST forest, recalled
through a structural-feature index, and finally aligned with an ordered tree/forest match. It never
calls a model: the retrieval is a local, reproducible computation over the assessed source tree, and
every match is only a *structurally similar location*. The class expansion pass still decides whether
that location is vulnerable, so a safe variant (for example the same operation with an added
ownership check) is deliberately still returned as a candidate.

Explore is a first-class pipeline stage: it opens its own audit session, so `workflow.log` shows
`[AGENT] explore: Starting (attempt 1)` / `[AGENT] explore: Completed (...)` and the per-agent
`agents/explore.log` records the pass, exactly like the model-backed agents.

The legacy normalized-token retriever (`normalized_token_clone_v1`, schema v2) is kept as an offline
baseline, not a production default. It is selected **only** when `SHANNON_EXPLORE_ALGORITHM` is set
to `token` / `v2` / `normalized_token_clone_v1`; unset, empty, unknown values, and `ast` / `v3` all
resolve to the AST structural retriever v3.

## Supported Languages

Two language families are parsed with Tree-sitter: the JavaScript/TypeScript family (`.ts`, `.tsx`,
`.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, `.cjs`) and Java (`.java`). A seed only matches forests from
its own language, so a renamed identifier or a different literal can never produce a false
cross-language hit. Any other extension is reported as an `unsupported_language` seed rather than
being parsed by a foreign grammar. A scan only indexes the languages that actually have an eligible
seed, so a Java-only job never reads the JS/TS sources (and the reverse).

## How It Works

1. **Seeds.** `runExploreAgent` reuses the existing trusted-sink extraction
   (`record_verified_finding_ids.json` plus each `*_exploit_collector_renumbered.json`, filtered to
   `status === 'exploited'`). Each recorded `workspace_relative_file_path` / `line_number` pair is
   deduplicated and resolved with `realpath`; paths outside the assessed repository, non-regular
   files, and unreadable files are rejected.
2. **Anchor.** The seed file is parsed with Tree-sitter and the recorded line is mapped onto an AST
   anchor, preferring a CALL / ASSIGNMENT / RETURN statement. A row that holds no statement widens
   by 2 lines on each side, and a line with several statements keeps at most 3 anchor alternatives;
   an anchor that cannot be resolved uniquely is reported as `anchor_not_found` /
   `ambiguous_anchors` instead of guessing one.
3. **Sink-anchored forest.** The anchor's whole statement subtree is the forest root, together with
   its neighbouring sibling statements (2 on each side) and up to 3 levels of `if` / loop / `try` /
   lambda control context. The forest never crosses a function boundary. Fewer than 12 nodes is
   reported as `forest_too_small`.
4. **Structural normalization.** Identifiers and literals collapse to `IDENTIFIER` / `LITERAL`, but
   `CALL`, `IF`, `RETURN`, `AWAIT`, operators, member/index access, and call arity survive, and
   parent/child edges keep their grammar field and order. Renames and literal swaps therefore do not
   change the structure, while differences in parent/child, sibling, or nesting relationships are not
   flattened away.
5. **Features and index.** Node categories, typed parent/child edges, depth-2 and depth-3 subtree
   shapes, control context, and a low-weight callee API label are extracted, weighted by inverse
   document frequency, and stored in one inverted index that all seeds share.
6. **Recall.** Candidate forests are scored by an IDF-weighted Dice coefficient; those at or above
   `minRetrievalScore` (0.25) are promoted to the expensive match, at most 100 candidates per seed.
7. **Ordered tree match and alignment.** Each promoted candidate is aligned with an ordered
   tree/forest edit match that allows whole statement subtrees to be inserted, deleted, or replaced,
   under a hard constraint that the seed anchor must map. A match needs `treeSimilarity >=
   minTreeSimilarity` (0.5), and `match_line` is the real executable statement line that the anchor
   maps onto — never the function head, window head, or synthetic root line. An anchor that cannot be
   mapped is dropped and counted under `unmapped_anchors`.
8. **Deduplicate and cap.** The seed's own location, overlapping hits in the same file, and duplicate
   `(finding, file, line)` hits are removed. Results are sorted by score, file, then line,
   interleaved across seeds, and capped per seed and globally. Exceeding a scan or match cap sets
   `truncated: true`; candidates are never dropped silently.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `minRetrievalScore` | 0.25 | Minimum IDF-weighted Dice recall admitted to the ordered-tree match |
| `minTreeSimilarity` | 0.5 | Minimum ordered-tree similarity for a reported match |
| `siblingRadius` / `maxAncestorDepth` | 2 / 3 | Sibling statements per side, and control-context levels kept in the forest |
| `maxForestNodes` / `minForestNodes` | 180 / 12 | Forest node bounds; whole statements are never cut |
| `maxAnchorAlternativesPerSeed` | 3 | Anchor statements considered per seed line |
| `maxCandidateForestsPerSeed` | 100 | Recalled candidates promoted to the ordered-tree match, per seed |
| `maxPreciseMatchesPerSeed` / `maxMatchesPerSeed` / `maxTotalMatches` | 10 / 10 / 100 | Output budgets |
| `baseWeights` | node 1, edge 2, shape2 3, shape3 4, context 2, api 1 | Base feature weights, multiplied by IDF |
| `maxMatcherCellsPerPair` / `maxMatchOperationsPerSeed` | 200k / 10M | Ordered-tree DP budget guards |
| `maxFiles` / `maxFileBytes` / `maxIndexedForests` / `maxCandidatesPerFile` | 5000 / 1 MB / 100000 / 400 | Repository scan caps |
| `maxSeeds` | 30 | Maximum seeds searched in one pass |

## Outputs

Explore commits four artifacts (plus removal of the retired template files):

- `explore_search_results.json` — the Expansion entry point, schema v3:

```json
{
  "schema_version": 3,
  "algorithm": "ast_structural_clone_v1",
  "matches": [
    {
      "finding_id": "INJ-01",
      "vulnerability_class": "injection",
      "seed_file": "src/orders.ts",
      "seed_line": 42,
      "match_file": "src/documents.ts",
      "match_line": 57,
      "candidate_start_line": 53,
      "candidate_end_line": 61,
      "score": 0.9474,
      "excerpt": "const document = await db.query(`SELECT id, title FROM documents WHERE id = '${docId}'`);",
      "ast_evidence": {
        "retrieval_score": 0.81,
        "tree_similarity": 0.9474,
        "anchor_confidence": 1,
        "seed_nodes": 24,
        "candidate_nodes": 27,
        "mapped_nodes": 22,
        "inserted_subtrees": 1,
        "deleted_subtrees": 0,
        "control_context_changed": false,
        "anchor_mapped": true
      }
    }
  ],
  "skipped_seeds": [],
  "truncated": false,
  "statistics": {
    "seed_count": 1,
    "eligible_seed_count": 1,
    "candidate_count": 1,
    "parse_failed_files": 0,
    "indexed_forests": 512,
    "retrieval_candidates": 14,
    "reranked_candidates": 1,
    "unmapped_anchors": 2,
    "ambiguous_anchors": 0,
    "matcher_budget_exceeded": 0,
    "parser_language_unsupported": 0
  }
}
```

- `explore_seeds.json` — every seed with its language, status, anchor line, anchor-candidate count,
  forest node count, context depth, and match count.
- `explore_clone_coverage.json` — `verified / eligible / skipped / indexed / matched / truncated`
  counts, per-reason skip totals, the per-seed records, and the new counters
  `parse_failed_files`, `indexed_forests`, `retrieval_candidates`, `reranked_candidates`,
  `unmapped_anchors`, `ambiguous_anchors`, `matcher_budget_exceeded`, `parser_language_unsupported`.
- `explore_deliverable.md` — a human-readable summary grouped by seed, with the ordered-tree match
  evidence per hit.

`match_line` is the candidate review anchor, not evidence that a vulnerability exists. The
expansion pass requires a submitted `sink` location whose range covers that exact line; naming the
same file is not enough. Similarity is only an admission signal: a safe variant with an added
authorization check is still returned and must be excluded by the expansion pass.

## Running the Tests

There is no repository-wide test runner. The retrievers have offline fixture tests that need a build
first:

```bash
pnpm install
pnpm --filter @shannon/worker check
pnpm --filter @shannon/worker build
node scripts/test-explore-ast-clone-search.mjs   # or: pnpm test:explore-ast
node scripts/test-explore-ast-activity.mjs      # or: pnpm test:explore-ast-activity
node scripts/test-explore-clone-search.mjs      # or: pnpm test:explore-clone (v2 baseline)
node scripts/test-record-explore.mjs
```

The AST fixture test covers the acceptance cases T01-T19: Type-2 rename/literal clones, Type-3
clones with an inserted statement, a deleted statement, and both, a safe clone with an added
authorization check, an unrelated implementation that shares only a method name, same-node-count
candidates whose parent/child structure differs (scored lower), a moved call whose control context
change is flagged, multi-anchor ambiguity, a nested call that never crosses the function boundary,
distinct skip reasons (parse error, missing file, unsupported language, out-of-range line, symlink
escape), a same-file twin with the seed excluded, Java retrieval with JS/TS language isolation,
Unicode/multi-line/CRLF line accuracy, enforced and disclosed budgets, deterministic byte-identical
repeat runs, stable ranking, and downstream admission of the exact AST-matched line. The activity
test drives the real `runExploreAgent` activity: default (no env) resolves to AST v3, an explicit
`SHANNON_EXPLORE_ALGORITHM=token` resolves to v2, seed gating keeps only record-verified exploited
findings, the committed artifact shape is checked, and re-running is idempotent.

## Known Limitations

- Structural only: no data flow, taint, or semantic (Type-4) matching, and no cross-language clones.
- Only the JavaScript/TypeScript family and Java are parsed; other languages are skipped as
  `unsupported_language`. A parse failure is reported as `parse_error` (counted in
  `parse_failed_files`) and is a different outcome from "no similar candidate".
- The tree similarity is a structural signal, not a vulnerability judgement.
- Large repositories are capped; inspect `truncated` and `explore_clone_coverage.json` before
  treating coverage as complete.
