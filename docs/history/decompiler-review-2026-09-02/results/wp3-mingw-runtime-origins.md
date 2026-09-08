# WP3 MinGW runtime-call origin transparency

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `5db4b91b` makes implicit MinGW `___main` removal transparent to statement
origin carriers. The cleanup still applies only to `_main`/`main`, a direct
zero-argument `___main`/`__main` call, and leaves every unrelated call or
statement unchanged.

The runtime call is deliberately deleted rather than translated into source
semantics. Its instruction mapping therefore disappears; it is not reassigned
to the following source call or return. Those surviving statements retain
their exact original owners.

## Focused evidence

The attributed-call test was observed red before repair because the wrapped
runtime call remained in the body. After repair it is removed while the
following call and return retain owners `0x401014` and `0x401018`.

```text
cargo test --features python-ext \
  ir::x86_prologue::tests::attributed_mingw_runtime_call_is_deleted_without_reassigning_its_owner \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::x86_prologue::tests
34 passed; 0 failed; finished in 0.20s
```

A fresh release extension was built in 34.97 seconds. The exact checked-in
MinGW PE32 `main` integration test remains green:

```text
uv run pytest -q \
  python/tests/test_pe32_cdecl_roundtrip.py::test_real_mingw32_main_has_bounded_cdecl_arguments
1 passed
```

No broad Rust, Python, architecture, fixture, or DecBench sweep was run.

## Next action

Audit the remaining raw statement readers in `src/ir/x86_prologue.rs` and
migrate the next enabled production omission with the same observed-red,
module-local, and exact-real-function sequence.
