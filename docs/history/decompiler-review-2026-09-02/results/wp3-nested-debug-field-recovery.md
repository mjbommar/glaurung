# WP3 nested debug-field recovery

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `99d7a68e` carries authoritative PDB aggregate layouts through the real
typed field pipeline and preserves expression origins while doing so. The
committed PE/PDB `record_value` fixture now renders:

```c
struct Point {
    int x;
    int y;
};
struct Record {
    unsigned char tag;
    int value;
    Point origin;
};
int record_value(Record *arg0) {
    return (unsigned int)(((unsigned long)((unsigned int)(arg0->value)) + arg0->origin.x));
}
```

Before this increment both field reads were raw `((long)arg0 + 0x4)` and
`((long)arg0 + 0x8)` integer-address dereferences.

This is a bounded WP3/WP8 output-quality slice, not completion of authoritative
SSA or general type recovery.

## Changes

- `src/ir/dwarf_fields.rs` treats expression-origin carriers as semantically
  transparent during pointer propagation and affine-address recovery, while
  preserving the carrier when it installs a `PdbFieldAddr`.
- `src/python_bindings/ir/dwarf_contracts.rs` accepts a bare typedef pointer
  only as a PDB lookup candidate. The matching PDB must return a complete
  aggregate of that exact name. The PDB's own struct/class/union kind remains
  authoritative, and CodeView scalar aliases such as `uchar` are normalized to
  standalone C.
- `src/ir/ast/dwarf_render_types.rs` validates by-value aggregate dependencies
  recursively and emits them in dependency order. Cycles, conflicts, malformed
  identifiers, guessed `long` widths, bad padding, and unknown field types
  still decline.
- `src/ir/dwarf_fields.rs` resolves an exact nested byte offset to a dotted
  member path only when one terminal field matches the load/store width.
- `python/tests/test_pdb_type_recovery.py` pins dependency order, scalar
  spelling, and both recovered field paths on the real committed fixture.

## Evidence

The end-to-end assertion was observed red after the first origin repair and
before PDB layout/render support:

```text
uv run pytest -q \
  python/tests/test_pdb_type_recovery.py::test_overwritten_win64_push_value_does_not_become_an_undefined_local
FAILED: `arg0->value` absent; both accesses were raw offsets
```

The required release extension was rebuilt after the final Rust changes:

```text
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv run maturin develop --release
Finished `release` profile [optimized]
Installed glaurung-0.1.0
```

Focused semantic and refusal tests:

```text
cargo test --features python-ext --lib ir::dwarf_fields::tests::
13 passed; 0 failed; 4,657 filtered out

uv run pytest -q python/tests/test_pdb_type_recovery.py
12 passed
```

The emitted translation unit is self-contained C:

```text
uv run python -m glaurung.cli decompile tests/pdb_types/types.dll \
  --func record_value --style decbench --no-color \
  --pdb-cache tests/pdb_types > "$HOME/.cache/glaurung/tmp/record-value-current.c"
cc -x c -std=c11 -Werror -c \
  "$HOME/.cache/glaurung/tmp/record-value-current.c" \
  -o "$HOME/.cache/glaurung/tmp/record-value-current.o"
exit 0
```

No broad fixture, Python, or DecBench suite was run for this bounded increment.
Concurrent decoder and source-analysis work remained unstaged and is not part
of the commit.

## Remaining boundary

The outer return still carries redundant unsigned widening casts. General
field recovery also remains limited to layouts and offsets that can be proved
exactly from authoritative debug information. Broader pointer/type constraint
recovery remains WP6/WP8 work; this increment does not infer aggregate types
from an arbitrary raw base register.
