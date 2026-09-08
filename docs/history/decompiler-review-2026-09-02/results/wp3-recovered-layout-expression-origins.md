# WP3 recovered-layout argument expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `bb98a3a9` gives arguments synthesized by the convention-generic
recovered-layout fold their exact setup-definition origins. It covers both the
all-adjacent form and the form that combines adjacent setup with proven live-in
storage.

When an adjacent setup reads a promoted spill, the argument additionally owns
the earlier definition that is substituted into it. The implementation merges
that contributor into the existing expression carrier rather than nesting
origin wrappers. Unchanged live-in arguments remain unowned unless their
reaching value already has provenance.

The existing safety boundary is unchanged: layout order, pure normalization,
removed-definition dependencies, intervening rewrites, live-in reachability,
and ambiguity checks still fail closed. This is provenance-only and does not
alter rendered or scored pseudocode.

Specialized cdecl32, hard-float, and table-call fallback producers remain open,
so call-argument expression attribution and WP3 are not complete.

## Focused verification

Two strengthened ownership cases were observed red before the production
change:

```text
attributed_recovered_layout_setup_folds_and_joins_the_call_owner
direct argument owner: None instead of setup owner 0x1010

attributed_recovered_layout_follows_a_pure_spill_definition
transitively substituted argument owner: None instead of 0x1010,0x1014
```

The exact cases then pass. The mixed live-in case was updated to inspect
semantic expressions through their carriers and proves that only the locally
defined argument receives setup ownership. The touched module is green:

```text
cargo test --features python-ext 'ir::call_args::tests::' --lib
111 passed; 0 failed; 4,249 filtered out; 0.22 seconds
```

The real-binary comparison used only `11_call_shapes::call_into_spill`, whose
eight-argument call exercises recovered callee layouts, across the relevant ABI
routes. Parent and isolated tip produce the identical result:

```text
host clang/gcc O0/O2:       4 pass
i386 O0/O2:                 2 pass
AArch64 O0/O2:              2 pass
ARMv7 A32 O0/O2:            2 pass
legacy ARMv7 O2:            1 pass
legacy ARMv7 O0:            1 pre-existing fail
```

The tip build guard reports fresh at exact commit `bb98a3a9`, with native
SHA-256 `fbb5deeb6b7fa785dbd209bb037d21a3bb9d1d5e27b6f2a98fb4e350f07cec70`.
The legacy `armv7:O0` baseline regression is identical on parent and tip and is
not attributed to this change. No full Rust, Python, fixture, architecture, or
DecBench suite was run.

## Next boundary

Migrate cdecl32 outgoing stack stores and lowered push pairs at their exact
argument-construction points. Each argument expression should own its value
store or push instruction, while padding, stack rebasing, cleanup, and the call
retain their existing statement-level ownership.
