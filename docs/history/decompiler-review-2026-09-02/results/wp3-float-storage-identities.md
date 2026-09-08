# WP3 float-storage identities

Commit `bde6dd82` makes production float-role projection retain semantic float
width across out-of-SSA coalescing. A rendered role may represent several
non-interfering SSA versions of the same VFP register, so requiring one exact
SSA identity discarded valid `float` and `double` facts. The projection now
uses the separately tracked physical-storage fact: one agreed canonical base
is accepted, while conflicting bases remain explicitly ambiguous and decline.

Two focused contracts cover the boundary. The positive test was observed red
before the production change because two `s15` versions produced no projected
type. It now projects `Float { width: 4 }`; a value combining `s15` and `s14`
still projects nothing. The complete owning module passes:

```text
cargo test --features python-ext python_bindings::ir::type_maps::tests::
24 passed; 0 failed; 4,640 library tests filtered out
```

After `uv run maturin develop`, a strict parent/tip A/B ran only these four
compiled functions:

```text
uv run python tools/dectest.py \
  172_float_double_widths:armv7:O0:accumulate_narrow \
  172_float_double_widths:armv7:O2:accumulate_narrow \
  172_float_double_widths:armv7:O0:accumulate_wide \
  172_float_double_widths:armv7:O2:accumulate_wide \
  --full --show --allow-stale
```

The failure classification is unchanged across the A/B. The new path does,
however, remove representation-only conversions where the storage evidence is
decisive: the O2 narrow loop changes coalesced integer temporaries into direct
`float` addition and multiplication, and the wide loops retain coalesced
`double` values instead of repeatedly unpacking and repacking integer bits.

The ARMv7 O0 `accumulate_narrow` cell is currently a baseline regression: its
body declares and reads `arg1`, but its signature exposes only `arg0`. Rebuilding
with this commit's production line reversed produces the identical missing
parameter and failure, so it is not attributed to this slice. The output is
still not execution-valid and this result does not claim the fixture green.

An isolated archive of `bde6dd82` records 5,194 declared Rust tests, 64 in
`python_bindings`, and zero tests outside every gate; all six census checks pass
after committing the generated baseline inside that archive. The live checkout
was not used for generation because concurrent uncommitted lanes contain their
own tests.

No broad suite, full fixture corpus, DecBench, or Joern ran. This advances WP3
storage identity consumption but does not complete the wider SSA migration,
conservative invalidation, or expression-origin work.
