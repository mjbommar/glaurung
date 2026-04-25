# Reviewer note — `MAIN__` @ 0x11f0 (gfortran main program)

## What the pipeline did
- **Reconstructed a Fortran program** from gfortran-emitted code: hello print, `command_argument_count` + loop summing `len_trim`, three summary PRINTs, then an inlined `my_sub` that bumps a SAVE'd counter and PRINTs twice.
- **Modeled the I/O descriptor** (`st_parameter_dt`) as an opaque `struct gfc_dt` with three named fields (`flags`, `filename`, `line`) — only those slots are touched in the pseudocode. Header re-stores before each `st_write` were *kept* (not dead-store-eliminated) because the line number genuinely changes per PRINT.
- **Collapsed the duplicated `L_1290` block** (decompiler rendered gfortran's do-while as two copies of the body) into a single `for (i=1; i<=nargs; ++i)` loop.
- **Inlined `my_sub`** at the call site: represented `&[var7+0x4014] += 1` as `++call_count_1` followed by the two trailing PRINTs.
- **Dropped** prologue/epilogue (callee-saves, 664-byte `sub rsp`, `rbp = rsp+128` frame-pointer setup) and renamed the gfortran mangled `call_count.1` to C-legal `call_count_1`.
- **Used `&dt`** explicitly as the first arg to all `_gfortran_*` calls; pseudocode relies on `rbp` as implicit rdi.

## Assumptions not mechanically provable
- **Stack-slot mapping is the main risk.** Rewriter assumed `rsp+4 = arg_index`, `rsp+8 = nargs`, `rsp+12 = total_len`, `rsp+16 = arg_buf[100]`. But the pseudocode writes `stack_3 = var6` (the running `total_len` accumulator) — and `stack_3` plausibly *is* `rsp+4`, which would mean total_len lives at rsp+4 and the slot mapping for the two integer PRINTs is **swapped**. The rewriter picked the "natural Fortran" mapping; the alternative inverts which value prints under "Number of arguments:" vs "Total argument length:" and also changes which variable's address is passed to `get_command_argument`.
- `0x600000080` interpreted as gfortran's list-directed/unit-6 transfer-flags word (named `GFC_IO_FLAGS`).
- `0x20c0` treated as the address of `global_counter` (a distinct global), not as the integer 8384.
- `_gfortran_iargc()`'s return is assumed to be captured into `nargs` (matches `stack_4 = ret` in pseudocode).

## Reviewer checklist
