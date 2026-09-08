# WP3 field-address expression-origin rendering

> **Kind:** record · **Date:** 2026-09-08

## Outcome

Commit `bb0052d6` makes the typed field-address reader transparent to a WP3
expression-origin carrier around an otherwise proven `PdbFieldAddr`. A field
load through a declared `struct node *` local now retains:

```c
return local_8->next;
```

Before the change, the outer metadata wrapper hid the field fact and expanded
the same expression into a raw address load and return conversion:

```c
return (node *)(*(long *)(((long)local_8)));
```

Only metadata became transparent. The existing proof still requires one
renderable hint, valid struct and field identifiers, an emitted complete struct
layout, a base register, and a valid scale/index combination. This is not a
claim that all PDB offsets are promoted to fields.

## Focused verification

The existing production typed-render contract was extended to return through
an attributed `PdbFieldAddr` while preserving its original promoted-pointer
lvalue checks. It was observed red before the one-line semantic-reader change
and passes after it:

```text
cargo test --features python-ext --lib \
  ir::ast::tests::promoted_pointer_slot_store_uses_the_declared_local_as_an_lvalue \
  -- --exact
1 passed; 0 failed; 4,669 filtered out
```

No test declaration was added, so the generated census does not change.

After `uv run maturin develop --release`, verification used the committed
`tests/pdb_types/types.dll` and `types.pdb` pair:

```text
uv run pytest \
  python/tests/test_pdb_type_recovery.py::test_overwritten_win64_push_value_does_not_become_an_undefined_local \
  python/tests/test_pdb_type_recovery.py::test_recovered_prototype_matches_the_source_declaration \
  -q
6 passed
```

An explicit release decompile of `record_value` succeeds and preserves its
authoritative `Record *arg0` signature, but its body still renders offsets
`+ 0x4` and `+ 0x8` rather than `arg0->value` and `arg0->origin.x`. That is
honest remaining field-recovery coverage, not a regression introduced here.

No broad Rust or Python suite, cross-architecture corpus, DecBench, or Joern
ran.

## Next boundary

Trace why the committed PDB fixture's proven layouts do not yet mark its simple
field offsets renderable, then add a fixture-backed positive field-promotion
contract before widening the rule. Continue the remaining expression-origin
semantic-reader audit independently.
