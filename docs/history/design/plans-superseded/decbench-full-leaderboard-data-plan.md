# DecBench full-leaderboard data completion plan

> **Kind:** record · **Date:** 2026-08-31

Status: execution in progress (run `20260831T180316Z`)  
Scope: one publication-quality Glaurung run covering every data-dependent element on
`https://decbench.com/`  
Primary corpus: DecBench `full`, 803 binary/config cells, 94,575 manifest functions  
Leaderboard presets: `unoptimized`, `optimized`, `inlined`, `large`, `sample-set`  
Modes per preset: ordinary and `normalize failures`  
Glaurung target: `7bc7353923cc659d3e970dbde8455b2b9b503a6d` (committed,
pushed, and frozen in a detached clean worktree)

Pinned inputs for the active run:

- Glaurung parent: `a34cab98cd9eae0c15763612c515c34f168aeb63`
- DecBench: `f76dae075d4d82004fb21132b3f15e43b680e179`
- dataset: `noelo-lab/decbench-dataset` at
  `e5eb576d66ee36793b800a4dd45e291e0add4472`, config `full`
- run root: `~/.cache/glaurung/decbench-submission/20260831T180316Z`

## 1. Outcome

Produce one canonical, independently verified Glaurung result that the DecBench
maintainer can merge as a replacement for the existing `glaurung` column without
rerunning, inferring, or fabricating any candidate-specific field.

Completion means all of the following are true:

1. The run uses the accepted DecBench Glaurung adapter contract on every binary.
2. Every one of the 94,575 manifest functions has an explicit Glaurung decompilation
   outcome, including failures.
3. Every metric value, perfect flag, distance, recompilation outcome, timing record,
   and candidate code sample required by the site is present at its native
   granularity.
4. One canonical `function_results.json` can generate every preset/mode combination
   with the pinned DecBench site builder.
5. Independent aggregation agrees with DecBench for Union and all three metrics.
6. The package carries immutable provenance for the dataset, Glaurung, DecBench,
   executables, commands, environment, and every submitted artifact.
7. The maintainer has no unresolved route, privacy, naming, version, or merge-policy
   decision when accepting the package.

“100% data coverage” does **not** mean Glaurung must successfully decompile every
function or that every metric must be measurable on every architecture. A real
failure remains a failure, and an architecture-wide DecBench abstention remains an
abstention. It means every expected cell has enough explicit evidence to distinguish
success, decompiler failure, and benchmark-tooling abstention without guessing.

## 2. Current evidence and why it is not the final submission

The completed `glaurung-229fbb1-clean` run is a strong scoring oracle:

- 803 C artifacts and 803 decompiler metadata TOMLs exist.
- 94,358 functions have candidate C and metric values.
- 217 manifest functions are absent from candidate output and remain misses where a
  metric is measurable for another column.
- Raw evaluated coverage is 88,963 GED values, 86,612 type-match values, and 94,358
  byte-match values.
- The independently audited full-corpus Union is
  `39,236 / 94,423 = 41.553435074%` when the new column is added alongside the
  published data.
- Pinned DecBench and the independent auditor agree on every headline count.

That run is not the final publication payload for four reasons:

1. It always used targeted `--vas`. The upstream DecBench adapter switches to
   `--all` above 400 targets; 55 binaries containing 65,742 manifest functions cross
   that threshold.
2. The exact scored Glaurung commit predates file/stdin-backed `--vas`, so the final
   adapter route must use a newer, explicitly pinned Glaurung revision.
3. The 116 sharded `function_results.json` files contain no per-function
   `compiles[glaurung]` entries. They retain only per-shard aggregate compile rates.
   Those aggregates cannot exactly populate the five preset-specific compile tables.
4. The evidence is distributed across shard JSON, evaluated TOMLs, decompiler
   artifacts, and provenance files rather than one site-schema-valid master result.

Preserve the old run unchanged. It is an oracle for regression and scoring checks,
not input to the new candidate column.

The new run is deliberately **not** a replay of `229fbb1`. Since that run, Glaurung
has added file/stdin-backed `--vas`, structured per-variable machine addresses in the
CLI JSON, narrower target-scoped batch output, and substantial core performance work.
The candidate must exercise those paths directly. The active run froze the pushed
revision above only after local `HEAD` and `origin/master` agreed.

### 2.1 Active-run evidence (not yet submission evidence)

As of 2026-08-31, the fresh full corpus is materialized and reconciled:

- 803/803 compiled binaries and 800 source CFG files are present; the three missing
  source CFGs are corpus-level absences, not download omissions;
- all 1,603 expected fetched files passed hash verification;
- the manifest contains 94,575 functions across 803 unique binary keys;
- the release extension is fresh, 2,754 Rust unit tests plus integration tests pass,
  and all 11 feature-build configurations pass;
- one full functional sweep reached 803/803 terminal binary outcomes and
  94,575/94,575 explicit function outcomes;
- 94,358 functions produced candidate C and 217 are explicit failures/abstentions;
- the successful identity set exactly matches `glaurung-229fbb1-clean`: 94,358 old,
  94,358 new, zero lost keys, and zero gained keys;
- raw conversion retained 390,349 structured variables and 181,561 direct machine
  addresses, with no out-of-target, duplicate-address, parse, or conversion errors.

The initial functional sweep ran on a loaded system and is therefore a coverage
oracle only. A subsequent idle-system concurrency probe produced byte-identical raw
JSON at 1, 2, and 4 workers and selected 4 workers (75.76 s, 48.15 s, and 30.78 s
respectively on the 21-binary Bash probe; peak per-process RSS approximately 241
MiB). The authoritative full decompilation then completed 803/803 binaries and
94,358 candidate bodies in 212.27 seconds wall time. Candidate/parent Criterion and
phase-profile comparisons, all-metric evaluation, and all ten site aggregates remain
required.

Two runner defects were found and repaired before accepting the coverage count:

1. dotted binary names were incorrectly shortened with `Path.stem`;
2. an ELF leading underscore was incorrectly treated as PE name decoration, merging
   distinct symbols such as `_rl_clear_screen` and `rl_clear_screen`.

Stale artifacts from the first defect were quarantined rather than reused. Targeted
repair after the second defect restored exact successful-key parity with the old run.

## 3. Site data contract

The final verifier must cover this matrix explicitly.

| Site element | Granularity | Required candidate fields | Completion condition |
|---|---|---|---|
| Union leaderboard | function x preset | `datasets`, `values`, `perfects` | all five presets build in both modes |
| GED leaderboard | function | GED value/perfect or explicit miss; shared source-CFG measurability | shared denominator identical across columns within each combo |
| Type leaderboard | function | type-match value/perfect or explicit miss | no value inferred from an aggregate |
| Byte-match leaderboard | function | byte-match value/perfect or valid toolchain abstention | abstention and failure remain distinct |
| Normalize failures | function x decompiler | explicit `decompiled[glaurung]` boolean | field present for all 94,575 manifest functions |
| Distance: GED | function | raw GED edit distance | distance present whenever GED was measured |
| Distance: types | function | `fp + fn` type-flip distance | distance present whenever type match supplied the required metadata |
| Distance: recompilation | function | changed assembly-line count | present for successful recompilations, absent for genuine non-builds/abstentions |
| Compiles | function | `compiles[glaurung]` boolean | present for every byte-match attempt with a matching recompiler |
| Pipeline health | function | decompilation attempted/succeeded and GED presence | source loss and Glaurung-output loss can be separated |
| Cost/time | binary and run | total wall time, function count, binary count, basis | all 803 binary timings represented exactly once |
| View samples | selected function | candidate C plus values/perfects | every selected non-malware sample either has code or an explicit candidate failure |
| Dataset page | group/function | labels, architectures, sizes, presets, dataset metadata | adding Glaurung does not change corpus identity or preset membership |
| Version/display | run | canonical id, full revision, display version, URL/license/privacy policy | no temporary column id leaks into publication |
| Snapshot/changelog | publication | generated timestamp, immutable snapshot, concise change record | published result remains citeable after future updates |

The site has ten aggregate combinations:

```text
unoptimized|0  unoptimized|1
optimized|0    optimized|1
inlined|0      inlined|1
large|0        large|1
sample-set|0   sample-set|1
```

For each combination the gate must validate `functions`, `binaries`, `overall`,
`per_metric`, `distance`, `compile`, and `errors`.

## 4. Immutable run layout

Create a new run root; never reuse or overwrite `decbench-full`:

```text
~/.cache/glaurung/decbench-submission/<UTC-run-id>/
  provenance/
    run.json
    environment.txt
    commands.jsonl
    hashes.sha256
    dataset-manifest.json
  worktrees/
    glaurung/
    decbench/
  tree/
    <opt>/<project>/{compiled,source_cfgs,decompiled,evaluated}/
  checkpoints/
    decompile/
    evaluate/
  shards/
  merged/
    function_results.json
    scoreboard.toml
    aggregates.json
    dataset.json
    samples.json
  audit/
    completeness.json
    replacement-diff.json
    independent-scores.json
    negative-controls.json
    site-schema.json
  submission/
    README.md
    manifest.json
    artifacts/
```

Set `TMPDIR` to a run-owned directory under `~/.cache/glaurung`; do not use `/tmp`.
All commands append a structured record containing start/end time, cwd, argv,
environment allowlist, exit status, and stdout/stderr log hashes.

## 5. Phase 0: agree on publication identity and route

### 5.1 Maintainer decisions

Before the expensive run, obtain written agreement from DecBench on:

- this is a full integrated-harness result, not an external sample-set submission;
- the accepted adapter uses the exact requested address set on every binary rather
  than switching semantic modes at 400 targets;
- address-based relabeling of stripped `sub_<va>` records to manifest names is the
  intended join operation;
- the publication id is `glaurung`, replacing the existing column atomically;
- the displayed version is the pinned full Git revision or an agreed release tag;
- candidate C may be published on the View page and in the dataset;
- malware/source privacy rules remain DecBench's existing rules;
- the maintainer will perform the final merge against the private master containing
  any non-public columns, such as private-artifact competitors.

Do not start the full run while any item is ambiguous. A technically complete result
can still be unpublishable if its route or identity was not accepted.

### 5.2 Version lock

Pin:

- the current DecBench `main` commit used for the site and scoring;
- the newest pushed Glaurung `master` commit containing file/stdin-backed `--vas`,
  structured variable addresses, narrow target-scoped JSON, and the finalized core
  performance work;
- the DecBench dataset full-config revision and manifest;
- Python, Rust, compilers, Joern, cross-toolchains, Capstone, and all lockfiles;
- the machine architecture and relevant resource limits.

The selected Glaurung commit must be built from a detached clean worktree with
`tools/build_guard.py` reporting `fresh`. Record SHA-256 for the CLI, native
extension, lockfiles, and source archive.

**Exit gate:** maintainer route accepted; both worktrees clean; all revisions and
binary hashes recorded; no human-readable short SHA is being used as proof.

### 5.3 Concurrent-agent commit and push handoff

Do not snapshot the current dirty shared worktree. Another agent owns the in-flight
performance refactor and is finalizing its commit and push. When that handoff arrives:

1. record the full local `HEAD` and `origin/master` SHAs independently;
2. require them to be identical before calling the candidate pushed;
3. inspect `git status --short` and distinguish unrelated local files from the
   committed candidate tree;
4. inspect the final commit/range and confirm it contains the intended performance,
   CFG/IR split, build-policy, CLI, and test changes;
5. record the candidate's parent SHA so performance and semantic deltas have a fixed
   comparison point;
6. create a new detached worktree from the remote SHA, never from the dirty shared
   checkout;
7. run `uv sync --locked --dev`, a fresh release build, and `tools/build_guard.py` in
   that detached worktree;
8. verify the detached worktree stays clean after all source/test gates.

If `master` advances again before the full run starts, either deliberately adopt the
newer remote SHA and repeat every gate, or keep the frozen SHA. Never silently move a
running benchmark to a later build.

For the active run, this handoff is complete: local `HEAD` and `origin/master` both
resolved to `7bc7353923cc659d3e970dbde8455b2b9b503a6d`, whose parent is
`a34cab98cd9eae0c15763612c515c34f168aeb63`. The detached run worktree, rather than
the shared checkout, is the build and test authority.

### 5.4 Latest-code acceptance gate

The latest changes are part of what is being submitted, so validate them before the
803-binary run rather than discovering a regression at the tail.

#### Functional parity and intentional deltas

- run the full project test suite from the detached candidate worktree;
- run the decompiler fixture/curriculum gates with the release extension;
- compare a fixed cross-architecture DecBench smoke set against the candidate's
  parent and against `229fbb1`;
- classify every C or metadata difference as an expected improvement, harmless
  nondeterminism, or regression;
- do not require byte identity when the new core intentionally improves output, but
  do require stable function identities and a reviewed semantic diff;
- repeat the smoke set twice and record nondeterministic functions separately.

#### Performance evidence

Measure release builds only; debug-profile speed is not representative. Use the
repository's Criterion pipeline/IR benches plus `tools/decompiler_profile.py` on a
fixed small/medium/large corpus. Record:

- cold and warm wall time;
- per-function and per-binary throughput;
- peak RSS;
- object-parse counts;
- pipeline phase timings under `GLAURUNG_PIPELINE_PROFILE=1`;
- output-function counts and artifact hashes beside every timing result.

Compare the candidate to its parent under the same machine state, process count,
toolchain, and input hashes. Performance is accepted only when output coverage does
not fall and any semantic output changes pass review. A faster run that silently
drops targets is a correctness failure.

Use the measurements to choose decompilation concurrency. Probe at least 1, 2, and 4
concurrent binary processes on representative large binaries; select the fastest
setting that stays below a documented RSS/load ceiling and produces identical
per-binary outputs. Do not assume that the ten-way evaluation concurrency is safe for
the heavier decompilation phase.

#### Narrow `--vas` output contract

Exercise all three VA transports—inline, `@FILE`, and stdin—and require byte-identical
JSON for the same ordered target set. For the benchmark route use one immutable
`@FILE` per binary, because it removes `ARG_MAX` and records the exact requested
addresses as a hashable artifact.

For target sets of 1, 400, 401, and the largest corpus binary, require:

- one analysis pass and no fallback to `--all`;
- no returned function outside the requested address set;
- exactly one record per recovered requested address;
- every unresolved requested address named on stderr and in the adapter failure set;
- stdout containing only the JSON payload, with profiling/diagnostics confined to
  stderr;
- stable core fields `name`, `entry_va`, and `pseudocode`;
- additive `size` and structured `variables` fields retained;
- variable `addresses` sorted, unique, inside the function's validated hot extent,
  and empty rather than guessed where the producer declines evidence.

This is “narrow” in execution and result membership, not a license to discard the
structured variable fields that the new CLI now provides.

## 6. Phase 1: make the upstream adapter route exact and testable

This work belongs in DecBench, with Glaurung tests guarding the CLI side.

### 6.1 Eliminate the 400-target semantic switch

Change `RawGlaurungDecompiler` so a known target set always invokes targeted mode:

- small sets may remain inline;
- large sets are written to a run-owned target file and passed as
  `--vas @<file>`;
- `--all` is used only when DecBench genuinely has no target set;
- Docker mode mounts the target file read-only or writes it inside a controlled
  container temp directory;
- the target file is retained or hashed into provenance until the process exits;
- cache keys include the exact sorted target set and Glaurung executable hash.

Tests must cover target counts of 0, 1, 400, 401, and more than 400, plus native and
Docker command construction. The 401 case must prove that `--all` is absent.

### 6.2 Join stripped results by address

The stripped CLI may return `sub_<va>` rather than the DWARF/source name. The adapter
must:

1. index returned records by normalized `entry_va`;
2. join each requested `(manifest_name, address)` by address;
3. relabel only the candidate function identifier needed by DecBench's name-keyed
   schema;
4. retain the recovered body, signature, control flow, and variables unchanged;
5. mark each requested address with no returned body as an explicit failed function;
6. reject duplicate returned addresses and returned addresses outside the request.

Tests must use a real stripped ELF and at least one PE fixture. Include a negative
test showing that an unrelated returned address cannot enter the manifest universe.

### 6.3 Consume structured variables and direct addresses

The current pinned DecBench adapter still constructs `variables=[]`, which discards
the latest CLI's structured variable inventory and forces type match through C-text
fallback. That is not acceptable for a latest-code submission intended to cover all
available data.

Update the DecBench consumer and model together:

- map Glaurung `name` and C `type` without rewriting them;
- map argument position to `VariableInfo.arg_index`;
- map frame storage/offset to DecBench's canonical `kind` and `stack_offset` only
  where the coordinate systems are proven compatible;
- carry `size` when Glaurung supplies it, otherwise leave it absent;
- extend the DecBench variable model to retain direct machine `addresses`;
- keep `line_mappings=[]` when no line provenance exists; direct addresses must work
  independently rather than being dropped with the empty line map;
- reject malformed, duplicate, out-of-function, or non-integer addresses instead of
  coercing them;
- preserve an explicit count of direct-only variables/functions for the audit.

Tests must cover x86-64, i386, AArch64, ARM32, a register argument with deliberately
empty addresses, and a local with multiple sorted direct addresses. Compare
structured-variable type-match against the C fallback on the smoke corpus and review
every score change before selecting the authoritative route.

### 6.4 Prove the leakage boundary

Add a command-capture integration test proving the Glaurung process receives only:

- stripped binary bytes;
- requested addresses;
- style, output-format, and resource-limit options.

It must not receive source text, source CFGs, DWARF types, expected C, or metric
values. Document that manifest names are used after execution only for the result
join.

### 6.5 Route equivalence smoke tests

For representative small and large binaries:

- run the adapter and an independently constructed targeted command;
- compare requested address sets, returned address sets, failed sets, and normalized
  emitted C;
- repeat once to test determinism;
- include ELF x86-64, ARM/Thumb, and PE32.

**Exit gate:** upstream adapter tests pass; 401+ targets remain targeted; stripped
name/address joins are complete; structured variables/direct addresses survive the
consumer boundary; no ground truth crosses into Glaurung execution.

## 7. Phase 2: preserve every per-function evaluation fact

### 7.1 Fix `FunctionData.compiles`

DecBench's `function_data_builder` currently records byte-match values and distances
but does not transfer `MetricValue.metadata["compilable"]` into
`FunctionRecord.compiles`. Add this at the original evaluation-to-function-data
boundary:

```text
if byte_match metadata contains "compilable":
    record.compiles[decompiler] = bool(metadata["compilable"])
```

Do not infer compilation from score, distance, or aggregate rate:

- a non-compiling function can still carry byte-match value `0.0`;
- a compiling function can fail later object extraction and have no distance;
- architectures without an installed matching recompiler abstain and must have no
  `compiles` entry, not `false`.

### 7.2 Persistence tests

Write RED tests before implementation covering:

- compilable true with changed-lines distance;
- compilable true with no changed-lines distance;
- compilable false with byte-match value `0.0`;
- toolchain abstention with no byte-match value and no compile flag;
- JSON round trip through `FunctionData.to_json/from_json`;
- `build_aggregates` preset-specific compile numerator and denominator;
- sharded `evaluate-tree` output preserving the same facts as a sequential run.

### 7.3 Preserve metric metadata needed for distances

Verify, by count and key identity:

- GED distance exists for every finite GED value;
- type distance exists whenever `fp` and `fn` exist;
- byte distance equals `changed_lines` for successful comparison;
- absence of byte distance has a classified reason: non-build, post-build extraction
  failure, metric error, or architecture/toolchain abstention.

If a reason is not currently serialized, add an enum-like per-function evaluation
status rather than overloading `false` or `null`.

**Exit gate:** a one-binary `evaluate-tree` run produces complete values, perfects,
distances, decompiled flags, and compile flags and survives JSON round trip.

## 8. Phase 3: build a resumable full-corpus runner

### 8.1 Decompilation

Run the accepted upstream adapter against a fresh materialized full tree. The runner
must checkpoint by `(opt, project, binary)` and record for every manifest binary:

- command and exact target-set hash;
- binary SHA-256 before and after stripping;
- Glaurung executable/native-extension hashes;
- start/end time and terminal status;
- returned and failed addresses;
- C/TOML artifact paths and hashes;
- function count reconciliation.

Resume only when all hashes and the column/version identity match. An existing file
without matching provenance is stale, not a valid checkpoint.

After each binary, validate:

```text
returned addresses subset of requested addresses
returned addresses disjoint from failed addresses
returned + failed = requested, unless a documented adapter-level terminal error
every C marker maps to exactly one manifest key
```

Also store the CLI JSON before DecBench model conversion. Validate the narrow-output
contract directly from that raw payload, then validate the converted
`DecompilationResult` separately. This makes a consumer mapping bug distinguishable
from a Glaurung production bug.

### 8.2 Evaluation

Evaluate GED, type match, and byte match with the pinned DecBench environment. Shard
only across disjoint `(opt, project)` groups. Each worker writes to its own group and
retains the full `FunctionData`, not only flat evaluated TOML aggregates.

For each binary require:

- a result file exists and parses;
- at least one function-level fact exists when the candidate produced functions;
- every evaluated function has a stored candidate artifact;
- no evaluated function lies outside the manifest;
- metric abstentions carry a classified benchmark/toolchain reason;
- byte-match attempts carry an explicit compile boolean;
- worker return codes and stderr are retained;
- no empty-success result is accepted.

Run serial repair only for classified incomplete cells. Never silently convert an
evaluation exception to an ordinary miss.

### 8.3 Measured time budget

Use the previous run only for scheduling:

- full targeted decompilation: reserve several hours and checkpoint continuously;
- ten-way sharded evaluation: previous measured wall time was about 87 minutes;
- merge/site/audit: reserve at least 30 minutes;
- one retry window for load-sensitive evaluation failures.

These are planning estimates, not completion evidence.

**Exit gate:** 803/803 binary outcomes terminal and classified; 94,575/94,575
manifest functions have explicit candidate success/failure state; every produced
artifact and result is hashed.

## 9. Phase 4: construct one canonical replacement column

### 9.1 Merge by immutable key

Use `(opt_level, project, binary, function)` as the only join key. Begin from the
maintainer's current master `FunctionData`, not the public subset if private columns
affect shared denominators.

For every manifest function:

1. remove every old `glaurung` entry from `values`, `perfects`, `distances`,
   `decompiled`, `compiles`, samples, versions, compile rates, and cost data;
2. insert the new facts under a temporary unique candidate id;
3. validate replacement deltas;
4. atomically rename the candidate id to `glaurung` only after all gates pass.

Do not add the candidate beside the old Glaurung column for publication. Addition is
useful for audit comparison but changes the shared measurable universe differently
from replacement.

### 9.2 Full-universe completion

The master must retain all 94,575 manifest rows. Set
`decompiled[glaurung] = false` explicitly for every requested manifest function with
no candidate body. Do not create metric values or compile flags for those misses.

Expected cardinality gates:

```text
binary groups                         = 803
manifest function keys                = 94,575
explicit decompiled flags             = 94,575
candidate C keys                      = decompiled true count
evaluated keys                        subset of candidate C keys
compile flags                         = byte-match attempted-with-toolchain keys
dataset tags                          unchanged from master
non-Glaurung facts                    byte-identical before vs after merge
```

### 9.3 Attach site extras

Populate without approximation:

- `decompiler_versions["glaurung"]` from the pinned build;
- structured variable records and direct machine addresses from the raw narrow CLI
  payload;
- per-function `compiles` from metric metadata;
- compile rates recomputed from those flags, not copied from shard averages;
- `cost_info.decompile_time["glaurung"]` from all 803 recorded binary timings;
- candidate code in the selected View samples;
- samples' values and perfect flags from the canonical records;
- any required hardest/history data, even if the current site does not render it;
- dataset info, source-loss data, labels, sizes, architectures, and preset membership
  unchanged from the master corpus.

**Exit gate:** one canonical `function_results.json` validates against the model and
contains no candidate fact that came from an aggregate inference.

## 10. Phase 5: independent completeness and anti-cheating audit

Extend `tools/decbench_audit_full.py` or add a submission-specific verifier. It must
fail closed on every condition below.

### 10.1 Corpus and artifact integrity

- dataset repo/revision/config match the accepted manifest;
- manifest contains exactly 803 binary keys and 94,575 unique function keys;
- no extra binary, function, metric, or decompiler key enters the universe;
- every true decompilation flag has exactly one candidate C marker;
- every candidate metric value has a candidate C marker;
- every false flag is backed by an explicit failed/unreturned outcome;
- all JSON/TOML numbers are finite;
- all files match the submission hash manifest.

### 10.2 Metric and denominator integrity

Independently recompute, for all ten combinations:

- function and binary membership;
- per-metric shared measurable universes;
- Union measurable universe;
- per-column perfect numerators;
- ordinary and normalized denominators;
- distance count/mean/median/at-zero;
- compile numerator/denominator;
- decompilation error numerator/denominator.

Assert that every decompiler shares one denominator for each metric in a given
combination. A candidate failure must stay in the denominator whenever anyone makes
that function measurable.

### 10.3 Replacement integrity

Compare master-before and master-after:

- the only candidate-scoring changes belong to `glaurung`;
- corpus, labels, datasets, source health, other decompiler values, and sample
  membership do not change;
- denominator changes are explainable solely by removing old-Glaurung-only coverage
  and adding new-Glaurung-only coverage;
- private columns remain present in the maintainer-side audit even if absent from the
  public package.

### 10.4 Negative controls

Run at least these controls on copied artifacts:

1. Change a recovered type and prove type match/perfect/Union move in the expected
   direction.
2. Change candidate control flow and prove GED moves.
3. Change a recompilable body and prove byte similarity or changed-lines moves.
4. Delete one C artifact and prove the audit rejects its metrics.
5. Delete one evaluated result and prove completeness fails.
6. Add a non-manifest function and prove universe leakage is rejected.
7. Flip a compile flag and prove the compile-table audit fails.
8. Replace a binary or executable hash and prove resume/provenance validation fails.

### 10.5 Sequential/sharded equivalence

Select at least one small, one large, one PE, and one ARM binary. Re-evaluate each
sequentially and assert function-level equality with its sharded results for values,
perfects, distances, compile flags, and classified abstentions.

**Exit gate:** independent report and DecBench report agree exactly; every negative
control is detected; no unresolved discrepancy remains.

## 11. Phase 6: build and inspect every site payload

Use pinned DecBench to generate:

```text
scoreboard.toml
data/aggregates.json
data/dataset.json
data/samples.json
```

### 11.1 Schema and numerical gates

For every one of the ten combinations:

- required keys exist for `glaurung`;
- denominators are nonzero where the preset has measurable functions;
- displayed percentages equal raw numerator/denominator calculations;
- distances have exact `n`, `at0`, mean, and median;
- compile data has a nonzero, justified denominator where byte-match attempts exist;
- pipeline error counts reconcile with explicit decompiled flags;
- no NaN, infinity, stale old-Glaurung version, or candidate id remains.

### 11.2 Rendered-page gates

Load the built site in a browser test and exercise:

- all five dataset buttons;
- normalize off/on for each;
- sorting by Union, GED, type, byte match, and compile percentage;
- the distance table;
- the compile table;
- pipeline-health output;
- cost/timing output;
- Glaurung samples on the View page;
- direct query URLs for every preset and normalized mode;
- snapshot rendering after publication.

Capture machine-readable DOM values and compare them to `aggregates.json`; screenshots
are useful review evidence but are not the numerical oracle.

### 11.3 Existing-site regression gate

Build the site once from master-before and once from master-after. Aside from:

- Glaurung's values/version/code/timing;
- rankings displaced by the new Glaurung values;
- shared denominators legitimately changed by Glaurung replacement;
- generated timestamps and the new snapshot/changelog entry;

all other site data must be identical.

**Exit gate:** every site control renders complete Glaurung data and agrees with both
the canonical payload and independent audit.

## 12. Phase 7: submission package and maintainer handoff

The package must include:

- a concise `README.md` with run identity, route, commands, known abstentions, and
  privacy choice;
- canonical Glaurung function records or a maintainer-reviewed merge overlay;
- all 803 C and metadata artifacts, unless privacy was explicitly requested;
- raw per-binary narrow CLI JSON and target-list hashes;
- per-function values, perfects, distances, decompiled flags, and compile flags;
- binary timing and cost summary;
- dataset/Glaurung/DecBench provenance and SHA-256 manifest;
- independent audit reports and their commands;
- site-schema report covering all ten combinations;
- sequential/sharded comparison report;
- negative-control report;
- expected replacement-only aggregate deltas;
- upstream PR/commit references for the adapter and compile-metadata fixes.

Send the package through the channel agreed in Phase 0. Ask the maintainer to run the
same verifier against the private master before publication and return the generated
`aggregates.json` hash for final comparison.

Do not call the submission accepted until:

1. the maintainer confirms the replacement merge used the intended candidate;
2. the live page shows the pinned Glaurung version;
3. all ten live combinations match the reviewed aggregates;
4. distance, compile, pipeline-health, cost, and View data are populated;
5. a dated snapshot exists;
6. the public dataset/index either contains the agreed artifacts or documents their
   approved privacy status.

## 13. Required implementation artifacts

Create or update these in small, reviewable increments:

1. Latest-code release/performance/semantic acceptance report tied to the pushed SHA.
2. DecBench adapter tests and target-file/address-join implementation.
3. DecBench structured-variable/direct-address model and adapter ingestion.
4. DecBench `FunctionData.compiles` persistence tests and implementation.
5. A resumable official-adapter full runner with immutable per-binary provenance.
6. A deterministic shard merger that emits one canonical replacement overlay.
7. A submission completeness verifier covering schema, provenance, artifacts, and
   all ten combinations.
8. A site payload/DOM verifier.
9. This document's execution diary or a sibling status file recording commands,
   hashes, counts, failures, repairs, and final live verification.

Each implementation follows repository TDD: RED, minimal GREEN, REFACTOR, focused
verification, then the full applicable gate. Keep Glaurung and DecBench changes in
their own repositories and commits; do not mix generated benchmark data into source
commits.

## 14. Stop conditions

Stop and do not submit if any of these is true:

- the maintainer has not accepted the adapter route;
- the candidate SHA is not committed, pushed, and identical to the frozen remote ref;
- a build hash cannot be tied to the pinned source revision;
- latest-code performance gains coincide with unexplained coverage or semantic loss;
- raw narrow CLI JSON is missing, contains out-of-target functions, or loses
  structured variable/direct-address fields at the adapter boundary;
- any binary lacks a terminal classified outcome;
- any metric-bearing function lacks a stored candidate artifact;
- any evaluated function lies outside the manifest;
- compile flags are reconstructed from aggregate rates or distances;
- the canonical master has fewer or more than 94,575 manifest functions;
- another decompiler's function facts change unexpectedly;
- independent and DecBench aggregates disagree by even one numerator or denominator;
- normalized-mode membership cannot be reproduced from explicit booleans;
- a negative control is not detected;
- the live site differs from the reviewed final aggregates.

## 15. Milestone checklist

- [x] M0: concurrent agent's candidate SHA is committed, pushed, and remote-verified.
- [ ] M1: publication identity, privacy, and exact-target adapter route accepted.
- [x] M2: clean Glaurung and DecBench revisions pinned; environment hashed.
- [ ] M3: latest-code semantic and release-performance acceptance gates pass.
- [ ] M4: 401+ target adapter test uses file-backed `--vas`, never `--all`.
- [ ] M5: stripped ELF/PE address joins and failure accounting pass.
- [ ] M6: structured variables/direct addresses survive CLI, adapter, and JSON round trip.
- [ ] M7: per-function `compiles` persistence passes JSON/shard/site tests.
- [x] M8: full official-adapter decompilation reaches 803/803 terminal outcomes.
- [ ] M9: all three metrics complete with no empty or unclassified result cells.
- [ ] M10: canonical replacement overlay covers 94,575/94,575 explicit outcomes.
- [ ] M11: timing, compile, distance, pipeline, variable, and sample extras are complete.
- [ ] M12: independent audit matches DecBench for all ten combinations.
- [ ] M13: negative controls and sequential/sharded replays pass.
- [ ] M14: generated site payloads and browser-rendered values agree.
- [ ] M15: maintainer private-master merge and live snapshot are verified.

Only M15 is “ready and added to every proper leaderboard element.”
