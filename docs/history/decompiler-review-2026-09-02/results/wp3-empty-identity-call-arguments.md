# WP3 empty-identity call-argument closure

> **Kind:** record · **Date:** 2026-09-12

Commit `22b3eb99` repairs plain/register-style call argument reconstruction
after the unified pipeline. That style deliberately keeps unnumbered LLIR, so
`prepare_llir_for_lowering_with_shadow` publishes a globally empty
`ValueIdentities` sidecar. The shared AST pipeline nevertheless passed it as an
authoritative identity source. Every ABI register then appeared to have no
identity, and `_start` degraded from a call beginning with
`__libc_start_main(main, ...)` to `__libc_start_main()` while its setup
assignments remained outside the call.

The argument-reconstruction boundary now treats a globally empty sidecar as
identity mode being unavailable and uses its established unnumbered path. A
non-empty sidecar remains authoritative per value: missing and conflicting
candidates still decline rather than falling back to register spelling.
`ValueIdentities::is_empty` checks every published fact collection, not only
the SSA-candidate map, so a sidecar carrying storage or role facts cannot be
silently downgraded.

The new contract was observed red before the fix. All owning call-recovery
tests, including the existing misleading-spelling and empty-sidecar frame
controls, pass:

```text
cargo test --features python-ext ir::call_args::tests:: --lib -q
132 passed; 0 failed; 4,680 filtered out
```

A release extension in the isolated verifier passes the exact real-binary
regression:

```text
uv run pytest \
  python/tests/test_cli_decompile.py::test_decompile_entry_prints_pseudocode \
  -q -vv
1 passed
```

The recovered startup call now renders six arguments beginning with `main`:

```text
call *(u64)__libc_start_main(main, %var0, (u64*)%rsp,
    (unsigned long)((unsigned int)(0)),
    (unsigned long)((unsigned int)(0)), %arg2);
```

The complete 37-test CLI decompile module then exposed one stale assertion:
the explicit-range test expected synthetic `sub_1840`, while WP2's unified
range/address pipeline correctly preserves the image symbol `_start`. Updating
that assertion to the current contract makes the module 37/37 green.

The required post-source-commit `pytest python/tests/ -x` gate passes the
repaired 8 and 11 percent stops and reaches the stale range-name assertion:
634 passed, 16 skipped, 128 deselected, three xfailed, and two subtests passed
in 170.53 seconds. This is a partial gate, not a whole-suite-green claim.

The isolated committed-source census now records 5,349 declared Rust tests and
zero outside every gate. Its growth is exactly the ratchet's 25-test refresh
threshold, so the generated baseline is committed with the test correction.
