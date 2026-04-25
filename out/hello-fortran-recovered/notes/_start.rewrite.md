# `_start` @ 0x1100 — reviewer note

## What the pipeline did
- Recognized this as the standard ELF `_start` ABI shim and replaced essentially all of it with a single C-visible `__libc_start_main(main, argc, argv, 0, 0, 0, stack_end)` call.
- Modeled `argc`/`argv`/`stack_end` via GCC `register __asm__(...)` bindings (`rdi`, `rsi`, `r9`) rather than as literal arguments — so the prologue's `pop`/`rsp`-manipulation is implicit, not coded.
- Translated the trailing privileged `hlt` to `__builtin_trap()` as a noreturn guard.
- **Dropped** the entire trailing block (`completed.0` load, compare to arg0, `*(off+0x3FE0)` deref, conditional indirect call). Justified as `__do_global_dtors_aux` that the disassembler glued onto `_start`.
- Discarded ABI plumbing with no C meaning: `rsp & ~15` alignment, `push ret`/`push rsp`, `nop` padding, ELF string-table noise.

## Assumptions not mechanically provable
- The tail block at/after `L_1158` actually belongs to `__do_global_dtors_aux`, not to `_start`. This is the most consequential assumption — if the disassembler's function boundary is right, a real conditional call has been deleted.
- Binary is a static / no-constructor build, so passing `0` for `init`/`fini`/`rtld_fini` is correct (pseudocode only shows `arg3=0`, `arg4=0`; `rtld_fini` in `rdx` is not visibly zeroed in the snippet).
- `stack_end` is delivered in `r9` at call time. Pseudocode shows `arg5 = arg2` (i.e. `r8 = original rsp`), so the actual register may be `r8`, not `r9` — the rewriter swapped which register binds `stack_end`.
- `__builtin_trap` (typically `ud2`/SIGILL) is acceptable in place of `hlt` (SIGSEGV). Semantically both are noreturn traps but the exact signal differs.

## Reviewer checklist
