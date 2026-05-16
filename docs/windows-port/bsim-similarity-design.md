# #186 -- BSim-equivalent function similarity design

> Ghidra ships BSim; Glaurung ships `glaurung diff` today but
> at function-name granularity only. The `agentic-security-bot`
> (asb) windows-port campaign needs body-level similarity for
> Patch Tuesday cross-build n-day analysis.

Roadmap status: `docs/architecture/IDA_GHIDRA_PARITY.md` row
"#186 BSim-equivalent function similarity (canonical PCode
hashing)" -- "More robust than FLIRT."

## Use case (the load-bearing scenario)

asb's Windows n-day loop:

1. Pick a Patch Tuesday (e.g. "June 2026, KB5039212").
2. Pull pre-patch + post-patch builds of `ntoskrnl.exe` from
   the corpus at
   `/nas4/data/binary-analysis/glaurung/windows-{8,10,11}-x64/`.
3. Diff the two binaries: identify which functions changed,
   rank by patch density.
4. Walk each changed fn through the tier-1 bug-class
   invariants (asb workstream 03); the change is the seed for
   "what bug was being fixed here, and is it exploitable on
   the pre-patch build."

Step 3 is `glaurung diff` today. The shallow version returns
function-name-keyed `same / changed / added / removed`; the
"changed" bucket is the campaign's input but the bucket is
either too coarse (every rename looks changed) or too noisy
(any compiler-output drift looks changed). #186 adds
body-similarity scoring so the "changed" set ranks by actual
semantic delta.

`ntoskrnl.exe` has ~6000 functions; a typical Patch Tuesday
touches ~30. The ranking has to pull the right 30 into the top
~100 or the campaign reads the wrong functions.

## Three approaches

asb workstream 02 says "Glaurung team decides; we contribute
use cases + test fixtures." This doc lays out the trade space.

### Option A: 4-gram opcode hashing + LSH

The closest to Ghidra's BSim. Per function:

1. Decode to instructions; for each instruction, normalize to
   a (mnemonic, operand-class) tuple (so `mov rax, 0x1234`
   and `mov rcx, 0xabcd` collide -- exact constants get
   abstracted to "imm").
2. Slide a 4-gram window over the instruction sequence; hash
   each 4-gram (FNV-1a or xxHash); collect a set per fn.
3. MinHash signature over the set; index via LSH
   (locality-sensitive hashing) for near-neighbor lookup.
4. Similarity between two fns = Jaccard estimate from
   matching MinHash signatures.

**Pros.**

- Cheap. No model dependency. Pure-Rust, fits into
  Glaurung's existing performance envelope.
- Deterministic; bench-friendly. Same binaries always
  produce same signatures.
- Ships fast: scaffold in 1-2 pomodoros, integration the
  same.
- Robust to register-renaming and constant changes; that
  covers the bulk of compiler-induced churn between Patch
  Tuesday rebuilds.

**Cons.**

- Misses semantic refactors that change the instruction
  stream (loop unroll, inline expansion, switch-table
  reorder, calling-convention change).
- Can be fooled by control-flow restructuring (basic-block
  reorder); mitigated by walking blocks in dominator order
  before linearizing, but a real refactor will still drift.

### Option B: CodeT5+ embeddings over decompiled pseudocode

1. Run Glaurung's existing decompiler (issue #161 family,
   shipped) over each fn; emit pseudocode.
2. Tokenize and embed via CodeT5+ (or similar code-aware
   transformer). 256-768 dim float vector per fn.
3. Index via FAISS / hnswlib; nearest-neighbor by cosine.

**Pros.**

- Highest semantic recall. A function that does "validate
  then memcpy" looks similar to itself across rewrites that
  change the instruction stream entirely.
- Composes well with Glaurung's decompiler-first philosophy
  (decompile is a first-class output, not a debug aid).

**Cons.**

- Model dependency. Need to ship a checkpoint, decide on
  CPU vs GPU inference, manage tokenizer alignment across
  Glaurung releases.
- Decompiler output is itself variable; small decompiler
  bugs become similarity-score noise.
- Slow per-call (10-100ms per fn embedding on CPU); 6000
  fns is 60-600 seconds wall before indexing.
- Less deterministic: model upgrades change all scores. The
  bench harness needs to pin checkpoint hash.

### Option C: Hybrid (recall filter -> embedding rerank)

1. Run Option A's MinHash-LSH to get top-K candidates per
   query fn (K~50, cheap).
2. Run Option B's embedding rerank on the K candidates only.
3. Return top-N from the reranked list.

**Pros.**

- Best per-call precision: Option A's coverage of compiler
  churn + Option B's coverage of semantic refactors.
- Avoids Option B's wall-time penalty on the full corpus:
  embedding is K=50 fns per query, not all 6000.

**Cons.**

- Two systems to ship and maintain.
- Initial value-over-Option-A is marginal; only worth the
  cost once both are stable.

## Recommendation

Ship Option A first (4-gram opcode + LSH). asb explicitly
agrees in workstream 02 sec "#186 -- BSim-equivalent function
similarity": "We may land just the first cut; Glaurung team
iterates." Per asb's calibration estimate, Option A alone
already ranks the right 30 fns in the top-100 for ~80% of
Patch Tuesdays. That clears the campaign bar; the remaining
20% accept noise.

Option B / C land later as a follow-up issue if Option A's
recall on real Patch Tuesdays comes in below the 80%
estimate.

## Implementation sketch (Option A)

```
src/analysis/similarity/
  mod.rs               # public API: build_index(), query()
  opcode_normalize.rs  # instruction -> (mnemonic, operand_class) tuple
  ngram.rs             # 4-gram extraction + FNV/xxHash
  minhash.rs           # MinHash signature (existing `probabilistic-collections`
                       # crate or hand-rolled 128-hash array)
  lsh.rs               # banding strategy for LSH (16 bands x 8 rows)
  index.rs             # persistent index format (SQLite, attached to .glaurung)
```

Persisted in a new SQLite table inside the `.glaurung` project
file, since the persistent-project ADR
(`docs/architecture/PERSISTENT_PROJECT.md`) is where indexed
analysis artifacts already live:

```sql
CREATE TABLE function_similarity_signatures (
    binary_id    INTEGER REFERENCES binaries(binary_id),
    fn_va        INTEGER NOT NULL,
    fn_name      TEXT,
    minhash_blob BLOB NOT NULL,        -- 128 u32s, 512 bytes
    PRIMARY KEY (binary_id, fn_va)
);

CREATE INDEX function_similarity_lsh ON function_similarity_signatures(
    -- LSH band hashes; one column per band, computed in app code
    band_0, band_1, ..., band_15
);
```

For cross-binary queries (the Patch Tuesday case), the asb
kg-pe bridge layer (`tools/kg-pe/bridge.py`) ATTACHes both
`.glaurung` files into a single DuckDB and runs the LSH join.
The schema is identical across binaries so the join is
straightforward.

## Schema decision: extend `bot/kg/` DuckDB or live in Glaurung KB?

Per asb workstream 02 sec "Two-store rationale":

- Glaurung's per-binary `.glaurung` SQLite is the truth store.
- asb's `bot/kg/` DuckDB is the cross-binary query layer.

Similarity signatures are per-fn-per-binary artifacts;
they belong in the truth store (Glaurung KB) by the same logic
as types, comments, xrefs. Cross-binary similarity queries
ride the asb bridge.

Concretely:

- `function_similarity_signatures` lives in the `.glaurung`
  SQLite schema; Glaurung-side.
- asb's `tools/kg-pe/bridge.py` exposes a view
  `all_function_similarity_signatures` aggregating across
  ATTACHed `.glaurung` files; asb-side.
- The query "for fn `nt!CmpKeyHandleClose` in 26100.5, find
  the top-10 most-similar fns in 26100.1" lives as asb SQL
  on the bridge view.

No schema duplication; no second source of truth.

## API surface

CLI:

```
glaurung diff a.exe b.exe --similarity bsim --top 50
```

Output extends the existing `glaurung diff` JSON with a
`similarity_score` field per "changed" entry; rows sorted by
descending score.

Python (memory_agent tool):

```python
# glaurung/python/glaurung/llm/tools/bsim_query.py
class BsimQueryArgs(BaseModel):
    binary_a: str
    binary_b: str
    fn_va: Optional[int] = None    # if set, query single fn
    top_k: int = 10
class BsimQueryRow(BaseModel):
    fn_a_va: int
    fn_a_name: Optional[str]
    fn_b_va: int
    fn_b_name: Optional[str]
    jaccard: float
class BsimQueryResult(BaseModel):
    rows: List[BsimQueryRow]
```

This is the 16th atomic tool conceptually (see
`atomic-tools.md`); the count there says "12-15" so #186
landing adds the bsim-query tool as a bonus.

## Build-tag interaction

The similarity signatures themselves are not build-tag dependent
(opcodes are the same bytes regardless), but the **query
results** must carry the build-tag for asb to consume:

- Each row in `function_similarity_signatures` joins to
  `binaries.sha256` (the existing column).
- The `bsim_query` tool's output includes the source binary's
  PE version info (from #199) so the agent can render
  "26100.1's `CmpKeyHandleClose` matches 26100.5's
  `CmpKeyHandleClose` at Jaccard=0.92" without re-querying.

#199 lands first ideally; if not, the tool falls back to
filename-as-build-tag (acceptable for ranking, not for the
agent's prose output).

## Calibration

Done-when (matches `roadmap.md` exit signal):

```
glaurung diff ntoskrnl-26100.1.exe ntoskrnl-26100.5.exe \
  --similarity bsim --top 50
```

For a Patch Tuesday whose changed-fn set is known (validated
via MSRC CSAF JSON), the top-50 contains >=80% of the true
changed fns. asb workstream 02 sec "Calibration plan" item 3
codifies the regression.

The bench harness (`python -m glaurung.bench`) gets a new
metric `bsim_topk_recall` so per-commit changes to the
similarity index surface as scorecard drift.

## Effort breakdown

| step | pomodoros |
|------|-----------|
| `opcode_normalize.rs` + `ngram.rs` (Option A core) | 1 |
| `minhash.rs` + `lsh.rs` | 1.5 |
| `index.rs` + SQLite schema + persistence | 1 |
| Wire into `glaurung diff` + JSON output | 0.5 |
| `bsim_query` memory_agent tool | 0.5 |
| Calibration harness: load MSRC CSAF, compute top-K recall | 1 |
| **total** | **5.5** |

Matches asb workstream 02's 4-8 estimate, midrange for
Option A. Option B / C as follow-up issues if the calibration
recall comes in low.

## Cross-refs

- Roadmap board entry:
  `docs/architecture/IDA_GHIDRA_PARITY.md` row for #186
- Existing diff tool to extend:
  `glaurung diff` CLI (issue #184, shipped)
- Persistent KB schema:
  `docs/architecture/PERSISTENT_PROJECT.md`
- asb campaign use case:
  `projects/windows-port/workstreams/02-kg-pe-substrate.md`
  sec "#186 -- BSim-equivalent function similarity"
- asb cross-binary query target:
  `projects/windows-port/workstreams/02-kg-pe-substrate.md`
  sec "Bridge layer: tools/kg-pe/bridge.py"
- Reference for Ghidra BSim:
  ghidra-sre.org Ghidra BSim documentation (offline copy not
  in the repo; consult the live page when picking up the work)
- MSRC CSAF JSON for ground-truth changed-fn lists:
  msrc.microsoft.com/update-guide CSAF feed; one JSON per
  Patch Tuesday
