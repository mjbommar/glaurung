# WP3 frame-spill type identities

Status: bounded production consumer migration landed at `5fcd345c` on
`agent/wp5-next-switch`.

## Result

Frame-relative pointer/type propagation now identifies frame bases through the
pipeline-owned `ValueIdentities` sidecar. Spill and reload slots are keyed by
the complete exact SSA identity plus displacement, rather than a parsed
`rbp#version` spelling. Pointer evidence therefore cannot cross between two
different lifetimes of the same architectural frame register.

The production typed renderer calls the identity-aware type-recovery entry
point. Bare type-recovery callers retain the pre-sidecar compatibility path.
Missing, ambiguous, or misleading identities decline frame classification.

## Focused evidence

```text
/usr/bin/time -v cargo test --lib --features python-ext \
  ir::types_recover::tests -- --nocapture
83 passed; 0 failed; 4,387 filtered out
elapsed 11.79 s; maximum RSS 2,861,944 KiB

uv run maturin develop
completed

/usr/bin/time -v uv run pytest \
  python/tests/test_cli_decompile.py::test_decompile_json_format_emits_valid_json -q
1 passed
elapsed 0.42 s; maximum RSS 76,616 KiB
```

Build fingerprint: commit `5fcd345c`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

Two exact unit contracts cover the new boundary: an opaque value with exact
`rbp` identity is a frame base while a misleading `rbp#3` mapped to `rax` is
not; and a spill through `rbp` version 1 cannot lend pointer type to a reload
through version 2.

## Measurement boundary

This is an identity-authority migration for typed output. The owning module,
including its real x86 and ARM type fixtures, is green; one production CLI C
path was exercised after rebuilding. No Rust fixture, GED, byte, Union, goto,
switch, break, or corpus-wide execution measurement was run. No broad suite,
fixture matrix, DecBench, or Joern ran.

## Remaining scope

This removes production display-name parsing from frame-base recognition and
spill/reload pointer propagation. Return-width refinement and other ABI storage
readers remain separate migrations. It does not complete the general WP6 type
solver, expression origins, or WP3.
