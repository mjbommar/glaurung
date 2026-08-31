# Reviewer note — `hello_program_main` @ 0x11f0

## What the pipeline did
- Recognised the libgfortran I/O sequence and folded the three independent stack-slot writes (`stack_0/1/2`) into a single fabricated `st_parameter_dt` struct with fields `common_flags`, `filename`, `line`. **Field offsets are guessed**, not taken from libgfortran headers.
- Collapsed the peeled first iteration + back-edge at `L_1290` into a single `for (i = 1; i <= nargs; ++i)` loop. The outer `%sle` guard means this is equivalent for `nargs < 1`.
- Renamed locals: `stack_4`→`nargs`, `stack_3`→`total_len`, `stack_5`→`i`, `(rsp+16)`→`arg_buf[100]`, `(rsp+4)`→`arg_index`.
- Modelled `0x20c0` as `global_counter` in a comment — but **the emitted code passes `(void *)8384`, not `&global_counter`**. After relocation these are not the same address.
- Modelled `*&[var7+0x4014]` as an extern `subroutine_invocations` and `call_count.1` as a file-static `call_count_1`. Address identity to the original symbols is not preserved.
- Inlined the trailing two `print` blocks (lines 40/41) directly into `MAIN__` rather than inventing a separate `my_subroutine()`, matching the fact that the binary makes no call there.
- Dropped prologue/epilogue (`push`/`pop`, `rsp -= 664`) as ABI scaffolding.
- Locally prototyped the libgfortran helpers; signatures match call sites but were not cross-checked against headers.

## Assumptions not mechanically provable
- `st_parameter_dt` layout (`long` + `const char*` + `int` + pad) matches what libgfortran actually expects at those byte offsets.
- `0x20c0` is the BSS address of the Fortran `global_counter` (and the rewrite's literal `(void*)8384` will resolve correctly — it almost certainly will not at link time).
- `var7+0x4014` and `call_count.1` are two *different* counters; they could be the same object accessed two different ways.
- Register pushes/pops carry no semantic meaning beyond callee-save.

## Reviewer checklist
