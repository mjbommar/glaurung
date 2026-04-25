# Review Note: `MAIN__` @ 0x11f0 (Fortran `PROGRAM main`)

## What the pipeline did
- **Struct synthesis**: Modelled the 528-byte rbp-anchored I/O scratch as `st_parameter_dt { common, filename, line, pad[512] }`. Only the three written fields are named; everything else is opaque padding.
- **Loop reroll**: The pseudocode shows an unrolled first iteration followed by a self-loop at `L_1290`. These were collapsed into a single `for (arg_index = 1; arg_index <= num_args; ++arg_index)`. This is the most significant structural rewrite.
- **Variable naming**: `stack_3 → total_len`, iargc result → `num_args`, `rsp+4 → arg_index`, `rsp+16 → arg_buf[100]`. Buffer size 100 taken from the literal arg passed to `get_command_argument_i4`.
- **Globals**: `&[var7+0x4014]` lifted to `extern int32_t global_counter`; `call_count.1` renamed to `call_count_1` (illegal C identifier otherwise). The pre-line-40 increment was inlined verbatim as the subroutine body — no wrapper function fabricated.
- **Cleanup**: Dropped optimizer-only stack reload chains (`stack_4`/`stack_6`) and the redundant double store of `stack_5`. Hoisted `SRC_FILE` so each descriptor setup uses the same constant.
- **Kept literal**: `0x600000080` is left as a single 64-bit `common` store rather than split into unit=6 / flags=0x80 halves, matching the single qword instruction.

## Assumptions not mechanically provable
- The reroll assumes the pre-loop block is just iteration 1 of the same loop (same callees, same args, same induction update). Not verified against source.
- `global_counter` and `call_count_1` symbol identities/linkage are guessed from offsets; the actual mangled names (likely `__modulename_MOD_global_counter` and `MAIN__.call_count.1`) are not preserved.
- Inlining the increment+two-PRINTs as "the subroutine body" is a guess — could equally be an internal/contained subroutine the compiler chose to inline.
- Line numbers (12, 25, 26, 27, 40, 41) are read directly from descriptor stores and trusted as-is.
- Equivalence was **not** checked by the verifier (LLM unavailable).

## Reviewer checklist
