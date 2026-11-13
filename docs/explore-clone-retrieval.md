# Explore Code-Clone Retrieval

The Explore stage turns record-verified sink locations into deterministic Type-2/Type-3 code-clone
candidates. It never calls a model: the retrieval is a local, reproducible computation over the
assessed source tree, and every match is only a *similar-looking location*. The class expansion
pass still decides whether that location is vulnerable, so a safe variant (for example the same
operation with an added ownership check) is deliberately still returned as a candidate.

Explore is a first-class pipeline stage: it opens its own audit session, so `workflow.log` shows
`[AGENT] explore: Starting (attempt 1)` / `[AGENT] explore: Completed (...)` and the per-agent
`agents/explore.log` records the pass, exactly like the model-backed agents.

## Supported Languages

Two language families are tokenized: the JavaScript/TypeScript family (`.ts`, `.tsx`, `.mts`, `.cts`,
`.js`, `.jsx`, `.mjs`, `.cjs`) and Java (`.java`). Each file is indexed with the tokenizer for its
own language, and a seed only matches windows from the same language, so an erased identifier or
literal cannot produce a false cross-language hit. Any other extension is reported as an
`unsupported_language` seed rather than being parsed by a foreign grammar. A scan only indexes the
languages that actually have an eligible seed, so a Java-only job never reads the JS/TS sources (and
the reverse).

## How It Works

1. **Seeds.** `runExploreAgent` reuses the existing trusted-sink extraction
   (`record_verified_finding_ids.json` plus each `*_exploit_collector_renumbered.json`, filtered to
   `status === 'exploited'`). Each recorded `workspace_relative_file_path` / `line_number` pair is
   deduplicated and resolved with `realpath`; paths outside the assessed repository are rejected.
2. **Seed window.** A representative anchor token is chosen on the recorded line (a call-shaped
   identifier if one exists, otherwise the rarest identifier, otherwise any token). A contiguous
   window of 80 tokens (clamped to 40-120) is centred on it. Fewer than 25 tokens is reported as
   `seed_too_short`.
3. **Normalization.** Tokens come from the scanner for the file's language (TypeScript scanner for
   the JS/TS family, a Java scanner for `.java`). Identifiers, strings, character/text-block
   literals, numbers, and regular expressions are erased to `IDENT` / `STR` / `NUM` / `REGEX`, while
   keywords, operators, and punctuation keep their shape. Renames and literal swaps therefore leave
   the token sequence unchanged (Type-2), and small inserted or deleted statements only break the
   few n-grams that span them (Type-3).
4. **Index.** Every source file in the repository is split into 50-150 token windows with a
   10-token stride. Each window's 5-grams are hashed and stored in one inverted index that all seeds
   share.
5. **Rank.** A window is scored by the fraction of the seed's 5-grams it contains. Windows below
   `initialSimilarityThreshold` or with too few shared n-grams are dropped, and overlapping windows
   inside one file are collapsed to their highest-scoring region so a repeated block cannot starve
   distinct candidates elsewhere.
6. **Align.** The strongest regions per seed are aligned with the seed using a longest-common-
   subsequence match over normalized tokens. The recorded line's anchor must appear in that
   alignment; the candidate token it maps to becomes `match_line`, and the matched span becomes
   `candidate_start_line` / `candidate_end_line`. A candidate whose anchor cannot be aligned is
   dropped (counted under `unaligned_candidates`) instead of guessing a line.
7. **Deduplicate and cap.** The seed's own window, overlapping windows of the same fragment, and
   duplicate `(finding, file, line)` hits are removed. Results are sorted by score, file, then line,
   interleaved across seeds, and capped per seed and globally.

## Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `kGram` | 5 | Token n-gram width for the index and the score |
| `seedTargetTokens` / `seedMinTokens` / `seedMaxTokens` | 80 / 40 / 120 | Seed window sizing |
| `minSeedTokens` | 25 | Below this a seed is skipped |
| `windowMinTokens` / `windowMaxTokens` / `windowStepTokens` | 50 / 150 / 10 | Candidate window geometry |
| `initialSimilarityThreshold` | 0.55 | Minimum seed n-gram containment |
| `minSharedKgrams` | 8 | Minimum shared n-grams for a candidate |
| `minAlignedSeedRatio` | 0.5 | Fraction of the seed that must align |
| `alignmentCandidates` | 20 | Distinct (non-overlapping) regions aligned per seed |
| `maxSeeds` / `maxMatchesPerSeed` / `maxTotalMatches` | 30 / 10 / 100 | Output budgets |
| `maxFiles` / `maxFileBytes` / `maxTotalTokens` / `maxWindows` | 5000 / 1 MB / 800k / 120k | Repository scan caps |

Exceeding a scan or match cap sets `truncated: true`; candidates are never dropped silently.

## Outputs

Explore commits four artifacts (plus removal of the retired template files):

- `explore_search_results.json` — the Expansion entry point. The top-level `matches` array is
  unchanged in shape; `regex` is replaced by clone metadata:

```json
{
  "schema_version": 2,
  "algorithm": "normalized_token_clone_v1",
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
      "excerpt": "const document = await db.query(`SELECT id, title FROM documents WHERE id = '${docId}'`);"
    }
  ],
  "skipped_seeds": [],
  "truncated": false,
  "statistics": { "seed_count": 1, "eligible_seed_count": 1, "candidate_count": 1 }
}
```

- `explore_seeds.json` — every seed with its token count, window line span, anchor, and status.
- `explore_clone_coverage.json` — `verified / eligible / indexed / skipped / matched / truncated`
  counts, per-reason skip totals, and the per-seed records.
- `explore_deliverable.md` — a human-readable summary grouped by seed.

`match_line` is the candidate review anchor, not evidence that a vulnerability exists. The
expansion pass requires a submitted `sink` location whose range covers that exact line; naming the
same file is not enough.

## Running the Tests

There is no repository-wide test runner. The clone retrieval has an offline fixture test that needs
a build first:

```bash
pnpm install
pnpm --filter @shannon/worker check
pnpm --filter @shannon/worker build
node scripts/test-explore-clone-search.mjs   # or: pnpm test:explore-clone
node scripts/test-record-explore.mjs
```

The fixture test recalls every labelled variant in the seed's Top-10 (Recall@10 = 100%): three
Type-2 rename/literal clones and three Type-3 clones (one with an inserted statement, one with a
deleted statement, one with both). It also covers a safe clone with an added authorization check, an
unrelated implementation that shares only a method name, seed self-exclusion, skip reasons (missing
file, unsupported language, too short, symlink escape), deterministic ordering, the global match cap,
and downstream admission of the exact match line. The Java fixtures repeat the same labelled set —
Type-2, Type-3, a safe variant, an unrelated file, and language isolation (a Java seed indexes only
the Java sources and never returns a JavaScript/TypeScript clone).

## Known Limitations

- Lexical/structural only: no AST, data flow, taint, or semantic (Type-4) matching, and no
  cross-language clones.
- Only the JavaScript/TypeScript family and Java are tokenized; other languages are skipped.
- The similarity score is a retrieval signal, not a vulnerability judgement.
- Large repositories are capped; inspect `truncated` and `explore_clone_coverage.json` before
  treating coverage as complete.
