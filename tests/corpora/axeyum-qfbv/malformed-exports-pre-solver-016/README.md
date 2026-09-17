# `malformed-exports-pre-solver-016` — scripts z3 itself rejects

> **Kind:** reference · **Status:** frozen (bug reproducers; never a benchmark)

These 735 `.smt2` files were captured into `shadow-splits/` by the two
`a6a5cc0` runs (Glaurung `a6a5cc02`, Axeyum `4b81e4de`, 2026-07-16) and moved
here on 2026-09-16. They are **not valid QF_BV**: the exporter of that day
rendered a `setcc` result (one bit stored into an eight-bit register slice) as a
57-bit `concat`, so the next `extract` is out of range. z3 4.13.3 rejects every
one of them —

| capture | files | z3's error |
|---|---|---|
| `tcpip-60s-a6a5cc0` | 733 | `(error "line N column M: invalid extract application")` |
| `dxgkrnl-60s-a6a5cc0` | 2 | `(error "... Argument #x0000000000000001 at position 1 has sort (_ BitVec 64) it does not match declaration (declare-fun bvadd ((_ BitVec 57) (_ BitVec 57)) (_ BitVec 57))")` |

— and Axeyum's strict sorts rejected them at capture time, which is exactly why
they were captured as "z3 decided, Axeyum errored" splits: the z3 *adapter* of
that day coerced the malformed child silently (and shifted the high half by one
bit instead of eight), so z3 in-process returned a verdict on a formula z3's own
parser refuses. The fix is
[`solver-016`](../../../../docs/decisions/solver-016-enforce-declared-concat-widths.md);
the pruning and its measurement are
[`solver-032`](../../../../docs/decisions/solver-032-axeyum-pin-bump-and-shadow-corpus-prune.md).

## Why they are kept

`solver-016` says "retain the old bytes as the reproducer", and these are the
only bytes that reproduce the pre-fix export shape. What they are **not** is a
solver corpus: every sweep that counted them as Axeyum misses was counting an
exporter bug (the improvement list of 2026-09-16 found 735 of 842 files under
`shadow-splits/` were these). Keeping them under a name that says so is the
whole point of this directory.

## Layout

Each capture keeps its original three-column `shadow-splits.tsv` rows for the
moved files (so `tools/axeyum/validate_shadow_splits.py <capture>` still
validates the inventory and hashes), plus `malformed.tsv`:
`sha256<TAB>z3 error line`. The `.smt2` files are Git LFS objects
(`.gitattributes`).

The live captures under `shadow-splits/` keep the remaining valid rows and
regenerated `summary-v1.json` / `capture-index-v1.json` / `manifest-v1.json`;
their `capture-v1.json` carries a `pruned` block pointing here. The run
statistics in `capture-v1.json` (`run.*`) still describe the original 2026-07-16
process and are not re-derived.

## Regeneration

Do not regenerate this directory. The gate that keeps `shadow-splits/` free of
this shape is `tools/axeyum/split_verdicts.py --check` (and, at capture time, the
z3-parses-it check that `GLAURUNG_DUMP_SHADOW_SPLITS` applies in a `solver-z3`
build, which writes such a query to `malformed.tsv` instead of
`shadow-splits.tsv`). If a future capture produces a z3-rejected script, that is
an exporter defect to fix, not a file to add here.
