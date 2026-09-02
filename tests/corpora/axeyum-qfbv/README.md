# `axeyum-qfbv` — QF_BV solver corpus and lineage-gate artifacts

> **Kind:** reference · **Status:** maintained

Real QF_BV queries that Glaurung's symbolic engine issued while analyzing
Windows drivers, plus the committed lineage-gate artifacts the axeyum/z3
comparison is scored against. These are inputs to `tools/axeyum/`, not
documentation; the capture protocol and the analysis of each artifact live in
[`docs/history/axeyum-integration-2026-07/capture-README.md`](../../../docs/history/axeyum-integration-2026-07/capture-README.md).

## Contents

| Path | What it is |
|---|---|
| `shadow-splits/<driver>-<secs>-<rev>/` | Four shadow-split captures: exact `<sha256>.smt2` payloads for occurrences where exactly one of z3/axeyum decided, plus `shadow-splits.tsv` (sha256, z3 class, axeyum class), `summary-v1.json`, `capture-v1.json`, `capture-index-v1.json`, and `manifest-v1.json`. Validated by `tools/axeyum/validate_shadow_splits.py`. |
| `lineage-*.json` (13 files) | Committed `lineage-gate-v1.json` baselines and candidates, compared by `tools/axeyum/lineage_gate.py compare`. |
| `manifest-representative-v1.json` | The manifest-v1 index for the representative pack built by `tools/axeyum/build_corpus.py`. |
| `excluded-hashes.txt` | Query hashes held out of the representative selection. |

`shadow-splits/**/*.smt2` are Git LFS objects (`.gitattributes`); a checkout
without `lfs: true` sees pointer files. The TSV and JSON indexes are ordinary
reviewable Git text.

## What the directory names encode

`<driver>-<solve-seconds>-<glaurung-revision>`. The revision is the short SHA
of the Glaurung commit the capture ran at, which is what makes two directories
for the same driver comparable:

| Directory | Driver | `IOCTLANCE_SOLVE_SECS` | Glaurung revision |
|---|---|---|---|
| `tcpip-60s-a6a5cc0` | `tcpip.sys` | 60 | `a6a5cc02` "capture exact shadow unknown splits" |
| `tcpip-60s-d60ed0f` | `tcpip.sys` | 60 | `d60ed0f5` "enforce declared concat widths" |
| `dxgkrnl-60s-a6a5cc0` | `dxgkrnl.sys` | 60 | `a6a5cc02` |
| `dxgkrnl-60s-d60ed0f` | `dxgkrnl.sys` | 60 | `d60ed0f5` |

## How to regenerate

Build `--example ioctlance --features solver-z3` (z3 is the trusted oracle),
point `GLAURUNG_DUMP_QUERIES=<dir>` at an empty directory and run the example
over the driver samples: the hook in `solve()`
(`src/symbolic/solver/mod.rs:622`) publishes each decided query as
`<sha256>.smt2` and appends `<sha256>\t<verdict>` to `index.tsv`, which
`tools/axeyum/build_corpus.py` then validates and turns into a hash-free
capture-index pack. The shadow-split captures use the sibling hook
`GLAURUNG_DUMP_SHADOW_SPLITS` (`mod.rs:723`) under
`GLAURUNG_SHADOW_DIFF=1` with both backends built, and are validated by
`tools/axeyum/validate_shadow_splits.py`. Never append a new experiment to an
existing capture directory. The exact driver list, environment variables, and
per-artifact acceptance criteria are in
[`docs/history/axeyum-integration-2026-07/capture-README.md`](../../../docs/history/axeyum-integration-2026-07/capture-README.md).
