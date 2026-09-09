# WP3 dynamic GOT targets

> **Kind:** record · **Date:** 2026-09-09

## Outcome

Commit `4f6762bc` repairs ELF GOT target extraction for linked images. Dynamic
relocation symbol indices belong to `.dynsym`; resolving them through the
ordinary symbol table caused common `R_X86_64_GLOB_DAT` entries to disappear.
The extractor now reads the object's dynamic relocation stream with its dynamic
symbol table while retaining the existing defined-symbol and nonzero-address
requirements.

For the visibility fixture, the extractor changed from an empty map to one
containing the link-time fact `0x3fe8 -> 0x4028` for `vis_public_bias`.

## Focused validation

A permanent regression test uses the committed `libmathlib.so` sample to prove
that a defined dynamic symbol is resolved from its loader relocation:

```text
committed_shared_object_resolves_a_defined_dynamic_symbol: pass
analysis::elf_got::relative_relocation_tests: 4 passed, 4,695 filtered out
```

No broad Rust or Python suite was run.

## Release real-binary evidence

A clean detached release build at `4f6762bc` reran exactly one differential
lane:

```text
157_symbol_visibility:gcc:O0:vis_read_bias  fail
SCOPED: 1 lane of 838 (0%) - no regressions in scope
```

The emitted C materially improved from an invalid read through the synthetic
GOT object:

```c
*(int *)(*(long *)(&glaurung_global_3fe8[0]))
```

to the correct named object:

```c
vis_public_bias
```

The lane remains red because the portable static declaration does not preserve
the original `.data` initializer value `11`. That is separate static-storage
initialization debt, not unresolved GOT linkage.

## Scope

This closes defined dynamic-symbol target availability for the measured ELF64
path. General cross-architecture dynamic relocation coverage, initialized
portable static storage, the visibility fixture's semantic xfail, and universal
WP3 attribution remain open.
