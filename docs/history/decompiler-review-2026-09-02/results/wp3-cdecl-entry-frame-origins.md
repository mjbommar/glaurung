# WP3 cdecl32 entry-frame origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `ce8d092a` makes the cdecl32 aligned-entry-frame recognizer transparent
to statement origins. Its exact structural proof still requires the aligned
entry stack, supported saved-entry forms, matched push/pop counts, recognized
frame reset, restored base, restored entry stack, and no surviving reads of the
machine registers or saved carriers.

The recognizer removes two disjoint machine ranges. Their provenance remains
disjoint: the synthesized prologue comment owns only entry alignment/frame
setup, and the epilogue comment owns only frame reset and restoration. The
surviving call and return keep their original owners.

## Focused evidence

The attributed entry-frame test was observed red before repair because none of
its eight statements collapsed. After repair it produces four statements with
owners:

```text
prologue comment: [0x1000, 0x1004, 0x1008]
call:             [0x100c]
epilogue comment: [0x1010, 0x1014, 0x1018]
return:           [0x101c]
```

```text
cargo test --features python-ext \
  ir::x86_prologue::tests::attributed_cdecl32_entry_frame_keeps_prologue_and_epilogue_owners_separate \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::x86_prologue::tests
33 passed; 0 failed
```

A fresh release extension was built in 35.21 seconds. The exact checked-in
MinGW PE32 `main` integration test remains green:

```text
uv run pytest -q \
  python/tests/test_pe32_cdecl_roundtrip.py::test_real_mingw32_main_has_bounded_cdecl_arguments
1 passed
```

No slow recompilation round trip or broader suite was run.

## Next action

Close the remaining small x86 raw readers, beginning with implicit MinGW
`__main` removal. A removed runtime call is genuinely deleted machine/runtime
semantics, so its mapping should disappear rather than migrate to an unrelated
source statement.
