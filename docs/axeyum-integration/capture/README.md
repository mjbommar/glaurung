# Glaurung QF_BV real-query corpus capture (for axeyum GQ1/GQ10)

Reproducible procedure for producing the lifter-shaped QF_BV query pack that
axeyum's `axeyum-bench` (manifest v1) ingests as its client-performance
corpus. The deduplicated corpus and the ordered native profile below are
complementary GQ1/GQ10 artifacts: the former controls cold policy comparisons;
the latter preserves occurrence order and client-boundary costs.

## What it produces

A manifest-v1 corpus (`.smt2` files + `manifest-representative-v1.json`):
distinct, deduplicated, well-typed QF_BV queries that glaurung's symbolic
engine actually issues while analyzing real Windows drivers, with each
query's **trusted verdict** (from the z3 oracle) and a structural `family`.

## Procedure

1. **Build glaurung with the trusted oracle** (z3 gives the authoritative
   verdict recorded in the manifest):
   ```
   cargo build --release --example ioctlance --features solver-z3
   ```

2. **Capture** (the `GLAURUNG_DUMP_QUERIES` hook in `solve()` writes each
   DECIDED query once as `<sha256>.smt2`, appends `<sha256>\t<verdict>` to
   `index.tsv`, dedup by content hash):
   ```
   export GLAURUNG_DUMP_QUERIES=/path/to/raw-corpus
   export IOCTLANCE_DEADLINE_SECS=400 IOCTLANCE_SOLVE_BUDGET=1000000 IOCTLANCE_SOLVE_SECS=600
   for drv in win10-vwififlt sqfs-intel-DptfDevGen windows-update-intel-audio-IntcSST; do
     cargo run --release --example ioctlance --features solver-z3 -- \
       samples/binaries/platforms/windows/vendor/realworld/$drv.sys >/dev/null 2>&1
   done
   ```
   (2026-07-13 capture: 15,687 distinct queries, 1,797 sat / 13,913 unsat,
   ~290 MB, sizes 30 B - 220 KB, p50 ~9 KB; 97% contain `extract`, 89%
   `concat` -- the width-mixed, extract/concat-heavy target distribution.)

3. **Build the manifest + tiers** (`build_corpus.py`: structural family
   classification, stratified `representative` tier + `full` tier, manifest
   in axeyum's v1 schema; `excluded-hashes.txt` drops the rare
   declared-vs-actual width edge cases axeyum's strict parser rejects):
   ```
   python3 build_corpus.py /path/to/raw-corpus /path/to/pack 6 excluded-hashes.txt
   ```

4. **Validate ingestion + profile** in axeyum:
   ```
   cd ~/projects/personal/axeyum
   cargo run --release -p axeyum-bench --features z3 -- \
     /path/to/pack --corpus-manifest /path/to/pack/manifest-representative-v1.json \
     --corpus-tier representative --backend sat-bv --compare-z3
   ```

## Result (2026-07-13, representative tier, 128 queries)

- **100% decided, 0 unsupported, 0 disagreements** (`manifest_agree=128`) --
  passes axeyum's full acceptance gate (exit 0).
- **Axeyum/Z3 ratio: 2.10x** (axeyum 272 ms, z3 130 ms) -- confirms the
  1.7-3.2x real-workload gap, measured through axeyum's own harness.
- **Cold-path attribution: bit_blast 42% + cnf_encode 42% = 84%, SAT 15%,
  model_lift 1%** (`sat_dominates: false`). The gap is in term->AIG->CNF
  lowering, NOT SAT search -- ranking axeyum's roadmap toward GQ3
  (coercion peepholes) / GQ4 (bit-slice) / GQ5 (AIG->CNF), deprioritizing
  GQ6 (SAT tuning).

## Hand-off

The representative pack is placed (uncommitted) at
`~/projects/personal/axeyum/corpus/glaurung-qfbv/` ready to ingest. The
full ~290 MB tier is regenerable via steps 1-3 (too large to commit; keep
access-controlled). `family`/`tiers`/`content_hash`/`expected` all conform
to `docs/user-guide/corpus-manifests.md`.

## Ordered native Axeyum profile

Build both backends so Z3 remains the authoritative exploration/model-choice
path while Axeyum receives the exact same query stream. On hosts where
`z3-sys` bindgen cannot find GCC's `stdbool.h`, include the GCC header path as
shown:

```sh
export BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/15/include
cargo build --release --example ioctlance --features solver-z3,solver-axeyum

profile_dir=$(mktemp -d /tmp/glaurung-axeyum-profile.XXXXXX)
GLAURUNG_SHADOW_DIFF=1 \
GLAURUNG_AXEYUM_PROFILE_DIR="$profile_dir" \
IOCTLANCE_DEADLINE_SECS=400 \
IOCTLANCE_SOLVE_BUDGET=1000000 \
IOCTLANCE_SOLVE_SECS=600 \
target/release/examples/ioctlance \
  samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys
```

`GLAURUNG_AXEYUM_PROFILE_DIR` must be set before the process's first native
check. It preserves the raw one-shot policy and writes one
`axeyum-profile-<pid>.jsonl` file per process. Each record carries the SHA-256
of the exact bytes produced by the existing SMT-LIB capture renderer, a
monotone process-local sequence, outcome/completeness, phase durations, and
AIG/CNF sizes. Query rendering/hash and JSON output are diagnostic overhead and
are deliberately outside `total_nanos`.

Validate and summarize from the Axeyum checkout:

```sh
python3 scripts/summarize-glaurung-native-profile.py \
  "$profile_dir"/axeyum-profile-*.jsonl \
  --manifest /path/to/pack/manifest-v1.json \
  --require-100-percent-decided \
  --out "$profile_dir/summary.json"
```

The summarizer fails closed on schema/order/completeness/count/policy drift and
on any overlapping manifest verdict conflict. Keep every JSONL occurrence:
deduplication would destroy the exact-repeat frequency and first-use/order
evidence needed by warm GQ7/GQ8 work. Run the same shadow command without
`GLAURUNG_AXEYUM_PROFILE_DIR` for an ordinary-wrapper timing control; do not
compare an Axeyum-authoritative run because different SAT models can change
Glaurung's exploration and query stream.

## Opt-in warm snapshot reuse (ADR-0164)

Glaurung commits `016935d` and `b09ec6b` add the first real warm GQ7 bridge.
The public `Solver` trait still submits complete assertion snapshots, but
`GLAURUNG_AXEYUM_WARM_REUSE=1` sends those snapshots through one retained
Axeyum arena/solver per explorer thread. The adapter translates structurally,
keeps the longest common assertion-root prefix active, pops the divergent
suffix, and asserts only the new suffix. It does not compare raw `ExprId`s
across cloned path pools, where sibling IDs may collide.

Run the same Z3-authoritative shadow stream with warm reuse enabled:

```sh
GLAURUNG_SHADOW_DIFF=1 \
GLAURUNG_AXEYUM_WARM_REUSE=1 \
IOCTLANCE_DEADLINE_SECS=400 \
IOCTLANCE_SOLVE_BUDGET=1000000 \
IOCTLANCE_SOLVE_SECS=600 \
target/release/examples/ioctlance \
  samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys
```

The footer adds `[axeyum-warm]` counters for checks, consecutive exact
snapshots, retained prefix roots, added roots, popped roots, and error resets.
Three alternating baseline/warm processes on 2026-07-15 each ran 13,126
same-stream checks with 13,126 agreements, zero disagreements/unknown splits,
identical findings, and zero warm resets. Median Axeyum time fell from 17.784
to 9.426 seconds (-47.0%); median paired Axeyum/Z3 fell from 2.648x to 1.462x.
Every warm run retained 679,870 prefix roots while adding 8,027 and popping
8,026; 5,609 snapshots exactly matched the immediately preceding snapshot.

This remains opt-in and is not the ordered warm-trace v1 deliverable. Snapshot
order cannot prove worker/path lineage, explicit scope history,
non-consecutive-fork reuse, or which model reads drove exploration. The next
capture must still emit the versioned worker/path/scope/model events in
Axeyum's `glaurung-ordered-trace-v1.md`; use it to compare explicit per-lineage
state against this snapshot inference and to publish p50/p95, memory, and
break-even depth before default enablement or verdict caching.

## Ordered lineage/scope/model trace v1

`GLAURUNG_ORDERED_TRACE_DIR` enables the separate GQ7 functionality artifact.
It must point at a parent directory, not at a shared output file. Each
`ioctlance` process writes a unique hidden temporary directory and publishes a
`glaurung-ordered-trace-<pid>-<uuid>/` child with one atomic rename only after
all paths are terminal and all repeated decided-query outcomes agree.

```sh
trace_root=$(mktemp -d /tmp/glaurung-ordered-trace.XXXXXX)
GLAURUNG_ORDERED_TRACE_DIR="$trace_root" \
GLAURUNG_TRACE_ORACLE_VERSION="$(z3 --version 2>/dev/null || printf unavailable)" \
GLAURUNG_SHADOW_DIFF=1 \
IOCTLANCE_DEADLINE_SECS=30 \
IOCTLANCE_SOLVE_BUDGET=20000 \
IOCTLANCE_SOLVE_SECS=60 \
target/release/examples/ioctlance \
  samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys

trace=$(find "$trace_root" -mindepth 1 -maxdepth 1 -type d \
  -name 'glaurung-ordered-trace-*' -print -quit)
python3 docs/axeyum-integration/capture/validate_ordered_trace.py "$trace"
```

The published directory contains `trace-manifest-v1.json`, the non-deduplicated
`events-v1.ndjson`, content-addressed exact scripts under `queries/`, and
`query-index-v1.json`. Every event has contiguous process/worker/path order.
Explorer roots and symbolic forks carry explicit parent lineage; every
persistent branch/concretization and temporary probe has matching
push/assert/check/pop history; SAT/UNSAT/unknown/error occurrences are retained;
and concretized/evaluated expressions that steer execution emit a model read
and named choice policy. Full query bytes come from the same
`solver::pipe::build_script` renderer as the cold corpus.

The validator fails on manifest/file hash drift, sequence gaps, missing path
terminals, broken lineage, scope underflow/digest mismatch, assertion/query
reconstruction mismatch, conflicting decided duplicates, query-index drift, or
a model read/choice that does not refer to a SAT check on the same path. This is
the producer-side T1 structural gate. Axeyum's independent strict QF_BV parse,
sort, replay, and model-choice satisfiability check remains the T2 consumer gate;
do not use a structurally valid producer trace alone to enable warm reuse by
default.

The first bounded real-driver sample on 2026-07-15 used the dual-backend shadow
path and a five-second new-function deadline. It published 8,153 events over
526 paths: 1,953 ordered checks (1,372 SAT, 581 UNSAT), 1,180 unique exact
queries, 1,404 push/assert pairs, 508 pops, 915 exploration-driving model
reads/choices, and 83 explicit UNSAT prunes. All 1,953 Z3/Axeyum verdicts agreed
with zero unknown splits, and the standalone validator accepted the artifact.
The unique-query count versus check count confirms exact repeats survive.

An earlier attempt was correctly retained as unpublished `.failed` evidence.
It exposed a Glaurung explorer bug: the feasibility shortcut treated a
symbol-free but syntactically nonconstant branch DAG as an independent symbolic
predicate, preserving a semantically UNSAT child until a later model read. The
shortcut now requires at least one free symbol before it may skip a check, with
a focused regression test. The corrected capture published without any
non-SAT model fallback. This behavior change is a correctness repair, not a
trace-only workaround.
