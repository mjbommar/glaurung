# Cross-name structural-fingerprint matching for `glaurung diff`

**Date:** 2026-05-25
**Target binary pair:** CVE-2026-41096 / dnsapi.dll (pre vs post)
**Status:** landed; tests passing.

## Problem

Pre-change, `glaurung diff` paired functions by their effective name
(PDB public symbol when available, `sub_<hex>` placeholder otherwise).
Functions that lacked a PDB symbol on both sides showed up as
`added`/`removed` even when the same function had just been moved by
the linker — its anonymous slot got a different VA, the placeholder
name changed, and the diff couldn't see they were the same body.

On the CVE-2026-41096 dnsapi.dll pre/post pair this dominated the
report: most of the unmatched rows were _the same function with a
shifted VA_, not real adds/removes.

## Approach (Diaphora-style structural rematch)

After the existing name-based pass, take every unmatched `added` row
and try to pair it with an unmatched `removed` row using the Jaccard
similarity of the per-block token-hash multiset already computed by
`structural_fingerprint.py` (its `FunctionStructure.block_token_hashes`).

The matcher is **greedy**: build the candidate pair list, sort by
similarity descending, lock partners as we go. A cheap **block-count
pre-filter** (within 0.75x..1.34x) cuts the worst-case cross product
before any hash-set intersection runs.

Pairs that score at or above `cross_name_threshold` (default `0.85`,
empirically calibrated below) collapse into one `changed` row whose
`a`/`b` fingerprints both populate and whose `similarity` field
records the score. PDB symbols on either side flow into
`public_name_pre`/`public_name_post` automatically.

## Numbers on dnsapi.dll

Both runs use `--include-anonymous --pdb-cache /nas4/data/symbol-cache/microsoft`.

| metric              | baseline (v2) | after cross-name (v3) |
|---------------------|--------------:|----------------------:|
| same                |          2911 |                  2912 |
| changed             |            22 |                   548 |
| added               |           539 |                    13 |
| removed             |           534 |                     8 |
| **added + removed** |      **1073** |               **21**  |
| cross_name_matched  |             0 |                   526 |
| wall-clock          |        14.6 s |                14.9 s |

The cross-name pass collapsed 526 `(added, removed)` pairs into
`changed` rows — total residual `added + removed` dropped from 1073
to 21, well under the target of 200. The pass added ~0.3 s on a
~3500-function binary; the bipartite work is tiny relative to the
disassembly cost that dominates the rest of the diff.

## Spot-check on cross-name matches

The five highest-quality renames the rematch surfaced:

| pre name (a)                   | post name (b)                                            | sim  |
|--------------------------------|----------------------------------------------------------|-----:|
| `sub_1800015d0`                | `Feature_2032384314__private_IsEnabledFallback`          | 1.00 |
| `WPP_SF_SSd`                   | `WPP_SF_SSD`                                             | 1.00 |
| `WPP_SF_Sid`                   | `WPP_SF_SiD`                                             | 1.00 |
| `WPP_SF__SOCKADDR_D`           | `WPP_SF__SOCKADDR_d`                                     | 1.00 |
| `sub_1800a366c`                | `sub_1800a5024`                                          | 0.95 |

All five look like legitimate rename or anonymous-VA-shift pairs:
the WPP_SF tracing helpers got case-flipped between builds; one
anonymous slot picked up a PDB symbol in the post build; one
anonymous slot kept its placeholder but shifted ~30 KB inside the
.text section.

## What still shows as added/removed (the 21 residual rows)

After cross-name matching the residual `added` set is 13 rows and
`removed` is 8. These should be inspected by hand — they're the
candidate for "real new code" / "real dead code" in the patch. The
JSON output has them with their PDB names (when available) and full
fingerprint payload.

## Schema / API changes

- `BinaryDiff` got two new fields: `cross_name_matched: int` and
  `cross_name_threshold: float` (`-1.0` sentinel = pass disabled).
- `diff_binaries()` got a new `cross_name_threshold` kwarg
  (defaulting to `CROSS_NAME_THRESHOLD_DEFAULT = 0.85`,
  `None` disables the pass).
- CLI: `glaurung diff --cross-name-threshold FLOAT` for tuning;
  `1.01` effectively disables the pass.
- JSON `schema_version` bumped to `"3"`. Added top-level
  `cross_name_matched` and `cross_name_threshold` fields. Per-row
  shape is unchanged; consumers that ignore unknown fields keep
  working.
- Markdown output now carries a one-line summary of the cross-name
  match count and surfaces rename pairs as `` `a_name` → `b_name` ``
  in the changed-functions table.

## Tests

- New: `python/tests/test_binary_diff_cross_name.py` (9 tests):
  greedy-best-partner correctness, below-threshold non-pairing,
  one-sided rows stay added, PDB-name propagation, threshold-None
  bypass, schema-3 JSON contents, switchy stripped/unstripped
  integration. Includes synthetic-structure unit tests that
  exercise `_rematch_unnamed_by_structure` without any binary
  fixture.
- All previously-existing `test_binary_diff.py` (9) and
  `test_structural_fingerprint.py` (5) tests still pass.
- `cargo test --lib` still passes (705 tests).
