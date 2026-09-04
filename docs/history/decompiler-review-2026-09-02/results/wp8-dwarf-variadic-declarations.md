# WP8 DWARF variadic declaration evidence — 2026-09-04

> **Kind:** record · **Date:** 2026-09-04

## Outcome

Glaurung now preserves the DWARF declaration fact that distinguishes
`f(fixed, ...)` from `f(fixed)`. The change is declaration-driven: it consumes
`DW_TAG_unspecified_parameters` and never guesses variadicity from a prologue.

The fact travels through:

1. `src/debug/dwarf.rs` (`DwarfFunction::variadic`);
2. `src/python_bindings/ir/dwarf_contracts.rs`
   (`DwarfPrototypeContract::variadic`); and
3. the authoritative `CallPrototype` consumed by the declaration plan.

Optimized concrete DIEs can inherit the marker from a same-unit abstract origin
or specification through a bounded 16-hop, cycle-refusing traversal. Unsupported
cross-unit references continue to decline rather than guess. PDB contracts set
the field to false because the current PDB adapter has no corresponding proven
fact.

## Real fixture evidence

The existing invariant source is
`tests/decompiler_fixtures/invariants/variadic_register_save_area.c`. It is
compiled independently under GCC and Clang at O0 and O2. The three source
variadic functions now render an ellipsis in all 12 cells. Clang's leading
`__attribute__((no_stack_protector))` also exposed and repaired a test-only
signature extractor assumption; the extractor now anchors the declaration to
the function body's opening brace.

The required RED state was captured before the implementation:

```text
uv run --no-sync pytest \
  python/tests/test_variadic_abi_invariants.py::test_a_recovered_variadic_prototype_declares_itself_variadic \
  -q --tb=short
12 failed
```

After `uv run maturin develop` and a fresh `tools/build_guard.py` result, the
whole invariant module reports:

```text
uv run --no-sync pytest python/tests/test_variadic_abi_invariants.py -q --tb=short
35 passed, 10 xfailed
```

The 12 source-interface cells are ordinary passes. The ten strict xfails are a
different remaining defect: emitted C does not yet fully reconstruct the SysV
register save area and `al` vector-argument-count input used by `va_start`.
Two GCC O2 functions already have no undefined reads and remain ordinary
passing controls. The former blanket xfail and its obsolete 5-to-38-read claim
were replaced with this exact failure surface.

Broader validation:

```text
cargo test --features python-ext
3,787 library tests passed, 4 ignored; all integration targets and doc tests passed

uv run --no-sync pytest \
  python/tests/test_decompiler_declaration_authority.py \
  python/tests/test_analyst_prototype_reaches_decompile.py \
  python/tests/test_pdb_type_recovery.py \
  python/tests/test_variadic_abi_invariants.py -q --tb=short
62 passed, 10 xfailed

uv run --no-sync pytest python/tests/test_test_census.py \
  python/tests/test_docs_contracts.py python/tests/test_docs_links.py -q --tb=short
62 passed
```

The focused declaration run initially found one stale test-only spelling
expectation (`void * p0` versus the renderer's existing `void *p0`); correcting
that expectation changed no product output.

## Scope and limits

This evidence proves trusted DWARF declaration fidelity for the real GCC/Clang
x86-64 fixture. It does not prove:

- generic variadic inference for stripped binaries;
- PDB variadic declarations;
- reconstruction of `va_start` or unnamed register arguments as valid C; or
- the still-open WP8 corpus-wide exit criterion.

No DecBench action or baseline refresh was performed.
