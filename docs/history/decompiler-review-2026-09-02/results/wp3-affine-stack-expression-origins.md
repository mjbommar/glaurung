# WP3 affine stack-address expression origins

Date: 2026-09-08

Commit: `b0a17c1e`

## Outcome

The bounded ARM stack-address alias expander now treats expression provenance
as transparent at each semantic classification boundary. This closes the layer
immediately downstream of the canonical frame-coordinate resolver repaired in
`e1e3784e`.

Optimized and A32 code commonly computes an address through a short chain such
as `index << 2`, `offset - 4`, and `offset + fp`. Before this change, attaching
an `Expr::Origin` to those definitions caused component sizing and expansion to
reject them. The final load retained artificial SSA temporaries instead of
recovering the frame-relative indexed address.

The repair covers:

- bounded affine-component sizing, including attributed constants;
- preservation of scaled register atoms beneath attributed operands;
- recursive expansion beneath an outer expression carrier; and
- copy-snapshot recognition through the semantic source view.

No limit was widened. Component/node caps, exact non-entry SSA identity,
single-linear-region scope, active-frame-base proof, and effect-free expression
requirements remain unchanged. Origin carriers remain on the expressions; only
read-only classification sees through them.

## Focused RED/GREEN evidence

The new attributed form of the existing A32 split-address contract is:

```text
ir::stack_locals::address_aliases::tests::attributed_ssa_stack_address_chain_is_expanded_by_identity
```

Before the repair it failed with `opaque_offset` still present in the final
address. After the repair it passes. The complete owning module—not the whole
Rust suite—also passes:

```text
running 8 tests
test result: ok. 8 passed; 0 failed; 4669 filtered out
```

The code was formatted with:

```bash
rustfmt --edition 2021 \
  src/ir/stack_locals/address_aliases.rs \
  src/ir/stack_locals/address_aliases/tests.rs
```

## Release fixture evidence

Validation used a detached clean worktree with only the owned patch, its own
virtual environment, and cache-backed target directory. This avoided both the
shared checkout's concurrent files and its installed extension.

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-origin-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/dectest.py \
  25_kmp_search:armv7_a32:O0:kmp_search --show
```

Result:

```text
SCOPED: 1 lane of 3304 (0%) - no regressions in scope
```

## Periodic Hello World checkpoint

Eight exact canonical cells sampled O0 and O2 across x86-64, AArch64, ARMv7,
and i686 MinGW. This was eight selected pytest nodes, not the 88-node Hello
collection and not the repository suite.

| Architecture | O0 | O2 | Current debt |
|---|---:|---:|---|
| x86-64 GCC, symbols PIE | pass | pass | none in these cells |
| AArch64, symbols PIE | pass | pass | none in these cells |
| ARMv7, symbols PIE | fail | fail | O0 frame artifacts; O2 four spurious parameters |
| i686 MinGW, symbols | fail | fail | string remains `(const char *)(0x404044)` |

Only ARMv7 could plausibly intersect this ARM address-expansion change. The
owned production lines were reversed, the release extension rebuilt, and only
those two cells rerun. Both failures reproduced with the change absent, so they
are confirmed pre-existing roadmap debt rather than regressions from
`b0a17c1e`. The MinGW failures are architecture-disjoint and were not rerun.

This increment advances WP3 expression-origin coverage. It does not claim the
periodic Hello grid is green, complete the remaining WP6/WP9 ARM signature and
frame work, or complete universal expression attribution.
