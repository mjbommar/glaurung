# WP3 opaque value identities through AST lowering

> **Kind:** record · **Date:** 2026-09-06

## Outcome

Behavioral commit `f05c9a5d` carries the authoritative SSA identity of a
value-numbered LLIR value beside the lowered AST instead of requiring a
consumer to recover that identity from a rendered `register#version` name.
`PreparedLlir` and `PreparedAst` retain the sidecar through the production
pipeline, and the exact float-role projection in the type-map boundary is the
first product consumer migrated to it.

Phi-copy coalescing can deliberately merge several non-interfering SSA values
into one C variable. The sidecar records every candidate and returns an exact
identity only for a singleton set. A coalesced value with two candidates
therefore declines the semantic query rather than selecting a version from
its display spelling.

This is a bounded WP3 increment, not completion. The sidecar currently covers
the primary LLIR definition/use model; multi-output intrinsics still inherit
the legacy primary-definition limitation. Most AST semantic passes have not
migrated, instruction origins are not implemented, and value numbering still
emits `#version` names for presentation and compatibility consumers.

## Changes

- `src/ir/value_number.rs` defines `ValueIdentities`, records opaque
  `SsaValue` identities while numbering definitions, uses, and phis, and
  preserves ambiguity after coalescing.
- `src/ir/value_number/coalesce.rs` returns the proved rename map so identity
  candidate sets follow the same coalescing decision as the numbered LLIR.
- `src/python_bindings/ir/pipeline.rs` carries the sidecar across LLIR-to-AST
  lowering and into the common renderer used by all four entry points.
- `src/python_bindings/ir/type_maps.rs` uses exact opaque register identity for
  float-role projection. Only compatibility callers without the production
  sidecar retain the display-name fallback.
- `tests/test_census_baseline.json` records three new Rust tests: two under
  `ir` and one under `python_bindings` (4,729 to 4,732 declarations).

## Verification

The focused Rust suites passed:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
cargo test --features python-ext opaque_ssa_identity_survives_llir_to_ast_lowering --lib
cargo test --features python-ext float_role_projection_uses_opaque_identity_instead_of_numbered_spelling --lib
cargo test --features python-ext coalesced_value_with_multiple_ssa_candidates_is_not_exact --lib
cargo test --features python-ext ir::value_number::tests --lib
cargo test --features python-ext python_bindings::ir::type_maps::tests --lib
```

The complete modules reported 46 value-numbering tests and 17 type-map tests
after the ambiguity contract was added. The release extension built with:

```bash
uv run maturin develop --release
```

The 19 focused Python entry-point-equivalence, determinism, and pipeline-profile
tests passed. The post-commit test-census suite passed all six tests.

The required full Rust gate passed at `f05c9a5d`:

```bash
cargo test --features python-ext
```

The library target reported 4,215 passed, zero failed, and five ignored. Every
integration and documentation target passed; the long CFR target reported 44
passed and ten ignored in 525.67 seconds.

The 419-pair identity-only output sweep used:

```bash
uv run python tools/stripped_differential.py --jobs 8 --json \
  > "$HOME/.cache/glaurung/tmp/wp3-identity-stripped.json"
```

Its JSON is byte-for-byte identical to the prior WP3 lifecycle map. Both have
SHA-256 `d86d3399127f93a292e895acc84375d2622065b9acf17d38228bb20973ca0c21`.
The command exits 1 for the same pre-existing stale improvement/regression
ratchet; there is no output change attributable to this identity-only slice.

The mandatory whole Python command completed red in 2,960.10 seconds:

```bash
uv run pytest python/tests/
```

It reported 87 failed, 4,711 passed, 881 xfailed, 79 skipped, and 128
deselected. The failing-node count equals the preceding WP3 lifecycle run, and
the focused identity tests are not among the failures. This is not an
exact-clean `f05c9a5d` Python claim: the process loaded the release extension
built from that commit, but the shared working tree acquired the next WP3
source, census, and documentation edits while it ran. Those edits directly
explain the build-guard, test-census, and two documentation-manifest failures;
other concurrent source-semantics work also remained in the checkout. The
exact 419-lane map and complete Rust gate are therefore the bounded causality
evidence for this slice; this overlay Python result records broad gate state
without pretending to be a clean A/B.

No DecBench run or upstream interaction was performed.

## Follow-on: key optimized DWARF locals by opaque identity

Commit `af65c260` migrates the second product consumer. Optimized DWARF
register-local recovery now matches a location-list register to the exact
architectural base in `ValueIdentities`; it no longer strips `#version` from a
numbered display name. A value with multiple identity candidates cannot claim
the source local, and an ambiguous pointer use fails the lifetime proof closed.

The existing seven DWARF register-local contracts pass together with a new
test whose numbered value is deliberately named `opaque-value`: its sidecar
still binds it to ARM `r4`, and adding a conflicting `r5` candidate makes the
same query decline. The release extension built successfully, all 19 focused
entry-point/determinism/profile tests passed, and the 419-pair output map is
again byte-for-byte identical with SHA-256
`d86d3399127f93a292e895acc84375d2622065b9acf17d38228bb20973ca0c21`.

This follow-on adds one `python_bindings` Rust test, moving the declared census
from 4,732 to 4,733. Its complete Rust gate passed:

```bash
cargo test --features python-ext
```

The command exited zero. Every library, integration, and documentation target
passed; the long CFR target reported 44 passed and ten ignored in 565.30
seconds.

The mandatory post-commit whole Python gate then completed from the committed
documentation state:

```bash
uv run pytest python/tests/
```

It reported 86 failed, 4,713 passed, 881 xfailed, 78 skipped, and 128
deselected in 2,867.08 seconds. The prior identity run reported 87 failed and
4,711 passed. The committed build and census state closed those two prior
bookkeeping failures. One apparently new node was
`gcc-O2-vsa_double_args` in `test_variadic_abi_invariants.py`.

An isolated release-built A/B proved that node passed at parent `f05c9a5d` and
failed at `af65c260`. Comparing the rendered function showed that the parent
was a false pass: display-name recovery conflated every `rax` lifetime with the
DWARF local `index`, thereby hiding the incoming SysV `al` vector-count read.
Opaque identity correctly sees several candidates for the bare kept-return
spelling, declines the local binding, and exposes the existing undefined
machine live-in as `ret`. The test inventory now records that cell as the same
strict xfail as the other unresolved variadic register-save-area lanes. The
complete variadic module passes with eleven expected xfails; only the already
repaired GCC O2 forwarding cell remains an ordinary pass. This is an honest
defect reclassification, not a claimed variadic-lowering repair.

## Follow-on: deterministic typed `ValueId`

Commit `e633ca41` interns one deterministic, opaque `ValueId` for every
recorded `SsaValue`. The numeric payload has no register, ABI, or presentation
meaning. Exact values expose one ID; coalesced values expose the complete ID
set and continue to refuse an exact answer.

The lookup derives through the existing authoritative candidate relation, so
rename, coalescing, and render-role projection preserve IDs without adding a
second per-name identity map. The only new persistent structure is the
`SsaValue -> ValueId` interning table.

Focused validation passed:

```text
opaque_ssa_identity_survives_llir_to_ast_lowering: 1 passed
coalesced_value_with_multiple_ssa_candidates_is_not_exact: 1 passed
opaque_value_ids_: 2 passed
```

This follow-on is a WP3 foundation, not an output-quality claim. No production
consumer reads `ValueId` yet, `tag_phys` remains, and rendered text is unchanged
by construction. No broad suite, fixture corpus, release rebuild, or Hello
matrix ran. The recent output-affecting pipeline work already retained selected
O2 Hello cells on x86-64, ARMv7, and AArch64, and the canonical 72-cell Hello
grid remains 72/72. A targeted cross-architecture Hello slice is due when the
first production consumer migrates to `ValueId`.
