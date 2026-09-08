# WP3 call-result identities

Status: bounded production consumer migration landed at `11a96792` on
`agent/wp5-next-switch`.

## Result

Call-result attribution now decides whether later expressions read an ABI
result register through exact `ValueIdentities`. Reads, overwrites, stack-address
expressions, nested control bodies, and the call-fold liveness check share the
same identity authority. A scratch value merely spelled `rax#version` can no
longer make an effect-only call render as producing a source value.

The exact positive case proves an opaque value with semantic `rax` identity is
still recognized. Missing or ambiguous production identities fail closed.
Compatibility callers without the sidecar retain the legacy spelling path.

## Focused RED/GREEN evidence

After correcting one test-fixture field name, the exact test was observed RED
only because `return_value_is_read_with_identities` did not exist. After the
implementation:

```text
/usr/bin/time -v cargo test --lib --features python-ext \
  ir::call_args -- --nocapture
130 passed; 0 failed; 4,338 filtered out
elapsed 11.44 s; maximum RSS 2,794,236 KiB

uv run maturin develop
completed

/usr/bin/time -v uv run pytest \
  python/tests/test_decompiler_fixture_harness.py::test_real_void_libc_call_is_not_rendered_as_a_value \
  python/tests/test_decompiler_fixture_harness.py::test_real_guarded_call_result_survives_a_noreturn_alternative \
  -q
2 passed
elapsed 2.56 s; maximum RSS 114,352 KiB
```

Build fingerprint: commit `11a96792`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

## Measurement boundary

This migration evaluated two directly owning C behaviors and no Rust fixture:
an effect-only libc call stays without a value assignment, and a consumed
guarded call result remains present. No GED, type, byte, Union, goto, switch,
break, or corpus-wide execution measurement was run. No full Rust/Python suite,
fixture matrix, DecBench, or Joern ran.

## Remaining scope

This removes production display-name parsing from call-result read/write
attribution. Other calling-convention storage readers in `call_args` remain to
be migrated or classified. It does not complete expression origins or WP3.
