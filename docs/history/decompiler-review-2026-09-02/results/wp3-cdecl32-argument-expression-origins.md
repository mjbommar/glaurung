# WP3 cdecl32 argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `e68ff86f` attributes cdecl32 call-argument expressions at both supported
construction points: contiguous stores into the preallocated outgoing `esp`
area and Iced's lowered right-to-left push pairs.

Each argument owns only the store that supplies its value. A lowered push's
stack decrement remains owned by the synthesized net `esp` adjustment. The
call statement retains the complete union of stores, decrements, and its own
call-site owner. Padding, rebasing, cleanup, gap, and caller-owned byte proofs
are unchanged.

This is provenance-only and leaves rendered/scored pseudocode unchanged.
Hard-float and table-call fallback argument producers remain open, so WP3 is
not complete.

## Focused verification

Both production forms were observed red before repair:

```text
cdecl32_folds_attributed_stack_stores_into_the_call_owner
first recovered argument owner: None instead of store 0x1014

cdecl32_attributed_pushes_preserve_call_and_adjustment_owners
first recovered argument owner: None instead of store 0x1026
```

After repair, both exact tests pass. The push test uses distinct decrement and
store addresses, proving that value and stack-motion ownership are not
conflated. The touched module remains green:

```text
cargo test --features python-ext 'ir::call_args::tests::' --lib
111 passed; 0 failed; 4,249 filtered out; 0.21 seconds
```

The real-binary canary is the eight-argument i386 `call_into_spill`. Exact
parent `bb98a3a9` and isolated tip `e68ff86f` release builds both report:

```text
uv run python tools/dectest.py '11_call_shapes:*:*:call_into_spill' \
  --arch i386 --jobs 2 --full
i386 O0 pass; i386 O2 pass; no scoped regressions
```

The tip build guard reports fresh with native SHA-256
`900c0434a45f93e40cc2bfe03508ab1849e11532ae924a8d3b4e35df246121a7`.
No full Rust, Python, fixture, architecture, or DecBench suite was run.

## Next boundary

Migrate the hard-float setup producer. Each VFP/core setup definition should
own only its corresponding source-ordered argument expression, while the call
continues to receive the complete consumed-setup union. Preserve the existing
homogeneous-float and mixed-bank allocation proof.
