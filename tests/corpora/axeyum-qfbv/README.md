# `axeyum-qfbv` — QF_BV solver corpus and lineage-gate artifacts

> **Kind:** reference · **Status:** maintained

Real QF_BV queries that Glaurung's symbolic engine issued while analyzing
Windows drivers, plus the committed lineage-gate artifacts the axeyum/z3
comparison is scored against. These are **inputs to `tools/axeyum/`**, not
documentation. The dated results and per-artifact acceptance analysis are in
[`docs/history/axeyum-integration-2026-07/capture-README.md`](../../../docs/history/axeyum-integration-2026-07/capture-README.md);
the live procedure is below.

## Contents

| Path | What it is |
|---|---|
| `shadow-splits/<driver>-<secs>-<rev>/` | Four shadow-split captures: exact `<sha256>.smt2` payloads for occurrences where exactly one of z3/axeyum decided, plus `shadow-splits.tsv` (sha256, z3 class, axeyum class), `summary-v1.json`, `capture-v1.json`, `capture-index-v1.json` and `manifest-v1.json`. Validated by `tools/axeyum/validate_shadow_splits.py`. Since 2026-09-16 every script here is one z3 parses: 107 files, all decided. |
| `shadow-splits/verdicts.tsv` | The regression set with known answers: one row per script under `shadow-splits/` (`capture`, `sha256`, z3 verdict, Axeyum verdict at the pinned rev). Written by `tools/axeyum/split_verdicts.py`; consumed by `tests/axeyum_shadow_split_verdicts.rs`. |
| `malformed-exports-pre-solver-016/<capture>/` | The 735 scripts the pre-`solver-016` exporter rendered with a mis-sized `concat`, which z3 itself rejects. Kept as bug reproducers, never counted as solver results; see its [README](malformed-exports-pre-solver-016/README.md). |
| `lineage-*.json` (13 files) | Committed `lineage-gate-v1.json` baselines and candidates, compared by `tools/axeyum/lineage_gate.py compare`. |
| `manifest-representative-v1.json` | The manifest-v1 index for the representative pack built by `tools/axeyum/build_corpus.py`. |
| `excluded-hashes.txt` | Query hashes held out of the representative selection. |

`shadow-splits/**/*.smt2` and `malformed-exports-pre-solver-016/**/*.smt2` are
Git LFS objects (`.gitattributes`); a checkout without `lfs: true` sees pointer
files. The TSV and JSON indexes are ordinary
reviewable Git text.

## What the directory names encode

`<driver>-<solve-seconds>-<glaurung-revision>`. The revision is the short SHA of
the Glaurung commit the capture ran at, which is what makes two directories for
the same driver comparable:

| Directory | Driver | `IOCTLANCE_SOLVE_SECS` | Glaurung revision |
|---|---|---|---|
| `tcpip-60s-a6a5cc0` | `tcpip.sys` | 60 | `a6a5cc02` "capture exact shadow unknown splits" — 733 of its 784 scripts were malformed exports and now live under `malformed-exports-pre-solver-016/` |
| `tcpip-60s-d60ed0f` | `tcpip.sys` | 60 | `d60ed0f5` "enforce declared concat widths" |
| `dxgkrnl-60s-a6a5cc0` | `dxgkrnl.sys` | 60 | `a6a5cc02` — 2 of its 4 scripts likewise moved |
| `dxgkrnl-60s-d60ed0f` | `dxgkrnl.sys` | 60 | `d60ed0f5` |

---

# Capture procedure

Three rules apply to every capture below, and violating any of them invalidates
the artifact rather than degrading it:

1. **Always capture into a new, empty directory.** Never append a new experiment
   to an existing one. Separate driver processes may append duplicate
   observations; the builder reconciles them and fails closed on any verdict
   conflict, which it cannot do across two experiments.
2. **Record the immutable Glaurung and axeyum revisions** with the artifact.
3. **z3 is the trusted oracle** for the recorded verdict. Build with
   `solver-z3` for anything whose verdict is going to be believed.

`export TMPDIR="$HOME/.cache/glaurung/tmp"` first; nothing here may write to
`/tmp`.

## 1. Deduplicated cold corpus (`GLAURUNG_DUMP_QUERIES`)

The hook in `solve()` (`src/symbolic/solver/mod.rs:627`, `maybe_dump_query`)
publishes each **decided** query as `<sha256>.smt2` and then appends
`<sha256>\t<verdict>` to `index.tsv`. Bytes are published collision-safely
*before* the index observation, so a torn capture is detectable.

```sh
cargo build --release --example ioctlance --features solver-z3

export GLAURUNG_DUMP_QUERIES=/path/to/new-raw-corpus     # must be new and empty
export IOCTLANCE_DEADLINE_SECS=400 IOCTLANCE_SOLVE_BUDGET=1000000 IOCTLANCE_SOLVE_SECS=600
for drv in win10-vwififlt sqfs-intel-DptfDevGen windows-update-intel-audio-IntcSST; do
  target/release/examples/ioctlance \
    samples/binaries/platforms/windows/vendor/realworld/$drv.sys >/dev/null 2>&1
done
```

## 2. Build strict capture-index packs

`build_corpus.py` validates every index row, verdict, filename/content SHA-256,
UTF-8 query and the complete raw-directory inventory *before* structural
classification and deterministic representative selection. It emits the
hash-free capture-index schema; there is deliberately **no exclusion
mechanism** at this stage — a rejected wide assertion is a producer or consumer
defect, not a benchmark result.

```sh
revision=$(git rev-parse HEAD)
source="Glaurung revision $revision; trusted solver-z3 capture; drivers <list>"
python3 tools/axeyum/build_corpus.py /path/to/new-raw-corpus /path/to/representative-pack 6 \
  --tier representative --full-out /path/to/full-pack --jobs 8 --source "$source"
```

Both output directories must be absent or empty. `--full-out` emits both packs
from one validation pass, so a large access-controlled payload is read once.
`--jobs` bounds the independent hash/UTF-8 validators while preserving
hash-sorted output; files are hard-linked where the filesystem allows.

If a widened full tier exceeds one process's memory, partition the *already
reconciled* pack into deterministic physical shards:

```sh
python3 tools/axeyum/shard_corpus.py /path/to/full-pack /path/to/full-shards --shards 4
```

`shard-set-v1.json` fixes the parent capture-index digest, the modulo rule, the
exact disjoint shard sizes and each child digest. Sharding never changes a
verdict and never lets a partial run be reported as full coverage.

Gates: `uv run pytest python/tests/test_axeyum_build_corpus.py python/tests/test_axeyum_shard_corpus.py`.

## 3. Shadow-split capture (`GLAURUNG_DUMP_SHADOW_SPLITS`)

Captures only the occurrences where **exactly one** backend decided — the
population that a verdict-agreement count is blind to. Requires both native
backends and a shadow mode (`GLAURUNG_SHADOW_DIFF=1` or `GLAURUNG_FAIR_SHADOW=1`);
`maybe_dump_shadow_split` is in `src/symbolic/solver/mod.rs`.

```sh
cargo build --release --example ioctlance --features solver-z3,solver-axeyum
GLAURUNG_SHADOW_DIFF=1 \
GLAURUNG_DUMP_SHADOW_SPLITS=/path/to/tests/corpora/axeyum-qfbv/shadow-splits/<driver>-<secs>-<rev> \
IOCTLANCE_SOLVE_SECS=60 \
  target/release/examples/ioctlance <driver>.sys
python3 tools/axeyum/validate_shadow_splits.py <that directory>
```

Name the directory `<driver>-<solve-seconds>-<short-rev>` so it stays comparable,
and add the `.smt2` files under the existing LFS filter.

In a `solver-z3` build the capture path parses every published script with the
linked z3 before indexing it: a script z3 rejects is appended to `malformed.tsv`
(`sha256`, error text) in the same directory and **never** to
`shadow-splits.tsv`. That is the check `solver-016`'s 735 malformed exports
would have failed. Then refresh the regression index and let its exit status
say whether the capture is clean:

```sh
python3 tools/axeyum/split_verdicts.py tests/corpora/axeyum-qfbv/shadow-splits \
  --z3 z3 --timeout 10                     # exit 1 on any z3-rejected or undecided script
cargo test --features solver-axeyum-text --test axeyum_shadow_split_verdicts -- --nocapture
```

The Rust test replays every row of `verdicts.tsv` through the pinned Axeyum and
fails on a decided verdict that differs from z3's, and on any row whose
committed Axeyum column is decided that the pinned solver no longer decides
(the **regression floor**). A row whose committed column is undecided is an
open capability gap: reported by name, never a failure, and promoted into the
floor once Axeyum decides it. With `GLAURUNG_SHADOW_SPLIT_AXEYUM_OUT=<file>` it
writes the per-script Axeyum verdicts, which
`split_verdicts.py --axeyum-results <file> --axeyum-note "..."` folds into the
committed index, printing `NEW:` and `PROMOTED:` rows by name.

### The tier: `scripts/shadow-capture.sh` (solver-034)

Everything above, in order, as one command -- build, capture over the four
July drivers (`--driver TOKEN=PATH` to choose others, `--ceiling` for the
per-function budget), sidecars, `split_verdicts.py`, the Rust replay, and the
fold -- with one exit status: a new split z3 decides and Axeyum does not is a
finding printed by name; a both-decided disagreement (bytes under
`<capture>/disagreements/`), a malformed export (`<capture>/malformed.tsv`),
a pinned script Axeyum stops deciding, or a driver that issued no checks
fails. `.github/workflows/shadow-capture-weekly.yml` runs it every Tuesday
and uploads the new captures and `verdicts.tsv` as an artifact; it commits
nothing. Each capture also carries `nondecisions.tsv` (`sha256`, the backend
that did not decide, its stable reason class), which the tier histograms.

```sh
scripts/shadow-capture.sh --ceiling 60 --out target/shadow-capture
# then, on green: git add tests/corpora/axeyum-qfbv/shadow-splits/{<new captures>,verdicts.tsv}
```

## 4. Ordered lineage/scope/model trace (`GLAURUNG_ORDERED_TRACE_DIR`)

The deduplicated corpus above destroys path, scope, occurrence and model-choice
order — exactly the facts a warm/incremental claim rests on. The ordered trace is
the separate producer for those. Point the variable at a **parent directory**,
never at a shared file: each process writes a hidden temporary directory and
publishes a `glaurung-ordered-trace-<pid>-<uuid>/` child with **one atomic
rename**, only after every path is terminal and every repeated decided-query
verdict agrees.

```sh
trace_root=$(mktemp -d "$TMPDIR/glaurung-ordered-trace.XXXXXX")
GLAURUNG_ORDERED_TRACE_DIR="$trace_root" \
GLAURUNG_TRACE_ORACLE_VERSION="$(z3 --version 2>/dev/null || printf unavailable)" \
GLAURUNG_SHADOW_DIFF=1 \
IOCTLANCE_DEADLINE_SECS=30 IOCTLANCE_SOLVE_BUDGET=20000 IOCTLANCE_SOLVE_SECS=60 \
  target/release/examples/ioctlance <driver>.sys

trace=$(find "$trace_root" -mindepth 1 -maxdepth 1 -type d \
  -name 'glaurung-ordered-trace-*' -print -quit)
python3 tools/axeyum/validate_ordered_trace.py "$trace"
```

A published trace holds `trace-manifest-v1.json`, the non-deduplicated
`events-v1.ndjson`, content-addressed scripts under `queries/` with
`query-index-v1.json`, and every asserted root independently under
`assertions/<sha256>.smt2` — including terminal branches that never reach a
check. Assertion bytes use the native backends' arbitrary-width truthiness
contract (`term != 0@width` for true, `term == 0@width` for false).

`validate_ordered_trace.py` is not optional tooling: **four Rust tests in
`src/symbolic/ordered_trace.rs` execute it**, so it must stay where
`ordered_trace.rs` expects it.

## 5. Native production-topology replay

New traces also carry `native-assertions/<pack-sha256>.json` expression-DAG packs
so a replay can drive the production native adapter without reparsing text. The
public SMT-LIB assertion stays the authoritative cross-tool identity: the replay
re-renders every imported pack through the text bridge and **rejects the pack**
unless the rendering hashes to the recorded constraint.

```sh
export GLAURUNG_AXEYUM_WARM_REUSE=adaptive
export GLAURUNG_AXEYUM_DIRECT_DELTA=1
export GLAURUNG_AXEYUM_SOURCE_REPO=/path/to/axeyum      # must be tracked-clean
/usr/bin/time -v target/release/examples/ordered_native_replay \
  "$trace" "$finding_sha256" "$offline_replay_sha256" /path/to/native-control-1.json
```

Fail the gate on any SAT/UNSAT opposition, operational error, synchronization
mismatch, warm reset, cache replay failure, or nonzero live path/owner/reference
gauge. Compare two reports only when their identities and exact-work inputs
match, keep honest `Unknown` counts visible, and never relax a predeclared
threshold after seeing a run — **a faster nondecision is not a result.**

## Regeneration gates

| Artifact | Validator |
|---|---|
| representative / full pack | `tools/axeyum/build_corpus.py`, then axeyum's own manifest generator hashes the bytes it will benchmark |
| shards | `tools/axeyum/shard_corpus.py` + `shard-set-v1.json` digests |
| shadow splits | `tools/axeyum/validate_shadow_splits.py` per capture; `tools/axeyum/split_verdicts.py --check` (z3 parses and decides every script, `verdicts.tsv` is current); `cargo test --features solver-axeyum-text --test axeyum_shadow_split_verdicts` (the pinned Axeyum decides every row like z3) |
| ordered trace | `tools/axeyum/validate_ordered_trace.py` (also run by `cargo test --features symbolic`) |
| lineage packs | `tools/axeyum/lineage_gate.py compare` |
