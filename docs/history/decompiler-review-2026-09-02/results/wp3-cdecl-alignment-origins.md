# WP3 cdecl32 call-alignment origin propagation

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `4dcaa1f5` makes balanced cdecl32 call-alignment cleanup transparent to
statement origins at top level and inside structured control. The existing
proof still requires adjacent padding, a recovered call, cleanup equal to
padding plus four bytes per argument, and no arithmetic overflow.

When that proof succeeds, the surviving call receives the deterministic union
of its original owner and the removed pre-call padding and post-call cleanup.
The structured carrier and unrelated statements retain their exact owners.
Mismatched cleanup remains visible.

## Focused evidence

The new nested attributed-call test was observed red before repair: wrapped
padding was not recognized and retained only its own owner. After repair, both
top-level and loop-body calls replace their three-statement sequences and own
the exact three-address unions.

```text
cargo test --features python-ext \
  ir::x86_prologue::tests::attributed_cdecl32_padding_moves_exact_owners_to_the_call \
  -- --exact
1 passed; 0 failed

cargo test --features python-ext ir::x86_prologue::tests
32 passed; 0 failed
```

A fresh release extension was built in 35.38 seconds. Two exact i386 O0 call
functions, including the directly relevant loop form, remain execution-correct:

```text
uv run python tools/dectest.py \
  '11_call_shapes:i386:O0:call_chain_in_loop' \
  '11_call_shapes:i386:O0:call_nested' --jobs 2 --full --show
2 function verdicts passed in 1 scoped architecture lane
```

No wider i386 or Python suite was run.

## Next action

Migrate the adjacent cdecl32 entry-frame recognizer. It removes two disjoint
machine ranges and synthesizes two comments, so the RED test must prove the
prologue and epilogue owners remain distinct rather than assigning the union of
the whole frame to both.
