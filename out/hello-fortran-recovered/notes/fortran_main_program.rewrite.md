# MAIN__ (gfortran main program) — rewrite notes

## What the pipeline did
- **Recognised libgfortran I/O idiom**: the three `stack_0/1/2 =` writes immediately before each `_gfortran_st_write` were folded into a single `st_parameter_dt` struct with fields `common_flags` / `filename` / `line`. The struct layout is **fabricated** to fit the observed writes; offsets were not cross‑checked against real libgfortran headers.
- **Collapsed the peeled loop**: the optimiser had peeled the first iteration (fall‑through into `L_1290` plus a back‑edge), guarded by an outer `if %sle goto L_12cc`. The rewrite presents this as a single `for (i = 1; i <= nargs; ++i)` loop.
- **Renamed locals from usage**: `stack_3` → `total_len`, `stack_4`/`var5` → `nargs`, `stack_5`/`ret` → `i`, `var2` slot → `arg_index`, `var4` → `arg_buf[100]`.
- **Inlined the "subroutine"**: the last two print blocks (lines 40/41) are modelled inline rather than as a separate function, since the binary does not actually `call` anything there.
- **Dropped ABI scaffolding**: prologue pushes, `rsp -= 664`, epilogue pops were removed.
- **Synthesised prototypes** for all `_gfortran_*` helpers locally; signatures match call sites but not necessarily libgfortran headers.

## Assumptions not mechanically provable
- The `st_parameter_dt` field layout (long, char*, int) — guessed from the write pattern, not verified.
- `0x20c0` is the address of a global `int` named `global_counter`. **The code does not honour this**: it casts the literal `8384` to `void*` instead of taking `&global_counter`. After relocation these are different addresses (see divergence).
- `&[var7+0x4014]` (a GOT‑relative store) is a distinct counter from `call_count.1`. Both were turned into separate C symbols; address identity with the original is lost.
- `call_count.1` (a gfortran‑mangled static) is modelled as a file‑static `int`, and `_gfortran_transfer_integer_write` is passed `&call_count_1`. The original pseudocode shows the symbol passed directly, which is consistent with "symbol = address", but worth a glance.
- `source_path` is a `const char[]` rather than a raw pointer; semantically equivalent for the cookie field.
- Loop‑skipping when `nargs < 1` is preserved by the `i <= nargs` condition (no separate guard needed).

## Known divergences carried forward
- **medium**: `0x20c0` is emitted as `(void *)8384`, not `&global_counter`. Comment and code disagree; at link time this references VA 8384, not the relocated symbol.
- **low**: `arg_index` is a fresh local each iteration instead of reusing the `(rsp+4)` slot — same semantics, different storage.
- **low**: `subroutine_invocations` lacks address identity with the original `var7+0x4014` location.
- **low**: ABI scaffolding (saves/`rsp` adjust) dropped.
