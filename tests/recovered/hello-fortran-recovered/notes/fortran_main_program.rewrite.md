## Reviewer note — `MAIN__` @ 0x11f0 (gfortran main program)

### What the pipeline did
- **Recognised gfortran I/O idiom**: collapsed the three repeated `stack_0/stack_1/stack_2` writes preceding every `_gfortran_st_write` call into assignments to fields of a single fabricated `st_parameter_dt` struct.
- **Re-rolled a peeled loop**: the pseudocode's unconditional fall-through into `L_1290` followed by a self-back-edge is the optimiser's peeled first iteration of the argument-walk. Rewriter folded it into one `for (i = 1; i <= nargs; ++i)` loop, gated by the existing outer `if %sle goto L_12cc` guard.
- **Renamed locals** by usage: `stack_4 → nargs`, `var6/stack_3 → total_len`, `stack_5 → i`, `(rsp+16) → arg_buf[100]`, `(rsp+4) → arg_index`.
- **Invented symbols** for raw addresses/labels: `0x20c0 → global_counter` (but see divergence), `&[var7+0x4014] → subroutine_invocations`, `call_count.1 → call_count_1` static.
- **Treated the trailing two print blocks as inlined** rather than synthesising a callee — the binary has no `call` for them.
- Dropped prologue/epilogue (`push`es, `rsp -= 664`, `pop`s) as ABI scaffolding.
- Prototyped libgfortran helpers locally with guessed-but-plausible signatures.

### Assumptions not mechanically provable
- Layout of `st_parameter_dt` (`long; const char*; int; pad[600]`) is **fabricated** to match the three observed stack slots; real libgfortran field offsets were not consulted.
- `0x20c0` is *assumed* to be `&global_counter`, but the emitted code passes the **integer literal `8384` cast to `void*`** — it does **not** take the address of the declared `global_counter` symbol. After relocation/linking these are different addresses.
- `&[var7+0x4014]` is modelled as a distinct extern (`subroutine_invocations`) from `call_count.1`; the binary may or may not have these be the same object.
- Helper prototypes (esp. arg count/order of `_gfortran_get_command_argument_i4`) are inferred from call shapes, not headers.
- Loop equivalence relies on the outer `nargs >= 1` guard genuinely skipping the body — looks right but worth a second look.

### Reviewer checklist