# WP3 return-width identities

Status: bounded production consumer migration landed at `a86966f1` on
`agent/wp5-next-switch`.

## Result

Typed-output return refinement now combines two authoritative facts: exact SSA
identity decides whether a definition belongs to the ABI result storage, and
the pipeline-owned definition-width map records whether that definition wrote
the narrow or full register view. This preserves the semantic difference
between `eax` and `rax` without parsing an opaque numbered name.

A value merely spelled `rax#version` but carrying exact `rdi` identity cannot
narrow the return. An opaque exact `rax` value with a four-byte definition does
refine to a four-byte integer. Missing or ambiguous identity declines the
production refinement; the no-sidecar compatibility API remains unchanged.

## Focused evidence

```text
/usr/bin/time -v cargo test --lib --features python-ext \
  ir::types_recover::tests -- --nocapture
84 passed; 0 failed; 4,387 filtered out
elapsed 11.67 s; maximum RSS 2,810,248 KiB

uv run maturin develop
completed

/usr/bin/time -v uv run pytest \
  python/tests/test_cli_decompile.py::test_decompile_json_format_emits_valid_json -q
1 passed
elapsed 0.38 s; maximum RSS 76,600 KiB
```

Build fingerprint: commit `a86966f1`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

## Measurement boundary

The owning type-recovery module, including its real x86 and ARM result tests,
is green; one production typed-output C path was exercised after rebuilding.
No Rust fixture, GED, byte, Union, goto, switch, break, or corpus-wide execution
measurement ran. No broad suite, fixture matrix, DecBench, or Joern ran.

## Remaining scope

This migrates the typed renderer's final integer return-width correction. It
does not replace the general WP6 constraint solver, migrate every ABI-storage
reader, or complete WP3 expression origins.
