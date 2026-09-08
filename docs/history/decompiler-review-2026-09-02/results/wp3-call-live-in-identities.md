# WP3 call live-in identities

Status: bounded production consumer migration landed at `b40b4226` on
`agent/wp5-next-switch`.

## Result

Production call-argument reconstruction now identifies a function's untouched
incoming ABI values through pipeline-owned `ValueIdentities`. The whole-function
inventory and every nested call-fold fallback share that authority. A register
that merely looks like `rdi#version` can no longer be injected as an incoming
argument when its exact identity belongs to another architectural register.

Legacy public entry points retain the spelling-based path explicitly when no
identity sidecar exists. The production entry point requires the sidecar and
fails closed for missing, ambiguous, later-version, or wrong-register facts.

## Focused RED/GREEN evidence

The exact test was first observed RED after its fixture syntax was corrected:
the compiler reported only that
`incoming_arg_expr_with_identities` did not exist. After implementation:

```text
/usr/bin/time -v cargo test --lib --features python-ext \
  ir::call_args::tests -- --nocapture
112 passed; 0 failed; 4,355 filtered out
elapsed 11.48 s; maximum RSS 2,795,372 KiB

uv run maturin develop
completed

/usr/bin/time -v uv run pytest \
  python/tests/test_cli_decompile.py::test_real_stripped_format_wrapper_recovers_forwarded_string_parameter \
  python/tests/test_cli_decompile.py::test_real_arm_hard_float_compare_does_not_erase_three_call_args \
  -q
2 passed
elapsed 0.74 s; maximum RSS 137,528 KiB
```

Build fingerprint: commit `b40b4226`, debug Cargo/maturin profile, CPython
3.14, and `python-ext` enabled.

## Measurement boundary

This identity-authority migration evaluated two directly owning C tests and no
Rust fixture. Both C checks are unchanged successes. No GED, type, byte, Union,
goto, switch, break, or corpus-wide execution measurement was run because the
change is intended to preserve valid output and reject only false spelling
matches. No broad Rust/Python suite, fixture matrix, DecBench, or Joern ran.

## Remaining scope

This removes the production `#version` parser used to select untouched incoming
call arguments. Other `call_args` spelling helpers still model value-numbered
storage and must be classified individually; pre-sidecar LLIR tagging and
explicit compatibility callers are not product identity omissions. WP3 remains
open until the complete semantic-reader and origin audits close.
