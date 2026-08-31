## `_start` @ 0x1100 — reviewer note

### What the pipeline did
- Recognized this as the standard crt1 `_start` ABI shim and rewrote it as a single C-visible call to `__libc_start_main(main, argc, argv, 0, 0, 0, stack_end)`.
- Modeled `argc`/`argv`/`stack_end` via GCC inline-asm register bindings (`rdi`/`rsi`/`r9`) instead of inventing fake locals or passing `0`/`NULL`. The values are effectively "whatever the kernel/loader left in those registers."
- Replaced the privileged `hlt` noreturn-guard with `__builtin_trap()`.
- **Dropped** the trailing block that loads `completed.0`, compares with `arg0`, then conditionally calls through `*(off+0x3FE0)`. The rewriter claims this is `__do_global_dtors_aux` that the disassembler accidentally concatenated onto `_start`, not actual `_start` code.
- Did not represent the stack-alignment (`rsp & ~15`), the `pop argc`, the `push ret/push rsp`, or the `nop` padding — declared as untranslatable ABI plumbing.

### Assumptions not mechanically provable
- The `completed.0` / `0x3FE0` tail truly belongs to `__do_global_dtors_aux`, not `_start`. If the disassembler's function boundary is correct, **a real indirect call is being silently dropped**.
- `init`/`fini`/`rtld_fini` are all `NULL`. Pseudocode only shows `arg3=0, arg4=0` being explicitly zeroed; `arg5` (rtld_fini in the SysV ABI register `r8`) is sourced from `arg2` (= original rsp), which contradicts passing `0` for it. The binding choices may be slightly off.
- `stack_end` lives in `r9` at call time. Pseudocode actually shows `arg5 = arg2` (i.e., `stack_end = saved rsp`), and `arg5` would normally be `r8`, not `r9`. Register choice is plausible but not verified.
- `hlt` ≈ `__builtin_trap()` is acceptable (both noreturn, both fault in userspace) but yields SIGILL rather than SIGSEGV.

### Bottom line
For a static-linker-emitted `_start`, this rewrite is conventional and almost certainly fine. The one item that genuinely needs a human eye is the dropped conditional indirect call — confirm it's `__do_global_dtors_aux` and not something the binary actually executes from `_start`.