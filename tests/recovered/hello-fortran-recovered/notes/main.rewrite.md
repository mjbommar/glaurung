# main @ 0x10d0 — Reviewer Note

## What the pipeline did
- Reconstructed the standard gfortran `main` stub: a C `main(int argc, char **argv)` that forwards to `_gfortran_set_args`, `_gfortran_set_options`, then `MAIN__`.
- **Renamed/cleaned**: dropped the `rsp = (rsp - 8)` prologue artefact and the explicit `ret = 0` temporary, collapsing to `return 0;`.
- **Symbol normalization**: rendered the mangled static `options.6.2` as plain `options` (assumed to be the file-scope options array declared elsewhere in the translation unit).
- **Argument restoration**: pseudocode showed `_gfortran_set_args@plt()` with no visible args; rewriter supplied `(argc, argv)` based on the well-known gfortran startup ABI.

## Assumptions not mechanically provable
- That the call to `_gfortran_set_args` actually receives `argc`/`argv` (the pseudocode dropped register-passed args). This is a convention, not a proof.
- That `options.6.2` and `options` refer to the same object — depends on a sibling declaration being recovered with the matching name.
- That `MAIN__` takes no arguments and returns void in the recovered header.

## Risk
Low. This is boilerplate emitted by gfortran for every Fortran program; behavioral surface is essentially fixed by the runtime contract.

## Reviewer checklist
- Confirm `options` is declared at file scope with the correct type/length expected by `_gfortran_set_options` (typically `int[7]`).
- Confirm the second arg to `_gfortran_set_options` is `7` matching the `options` array length, and that the array contents match the original `options.6.2` initializer bytes.
- Verify prototypes for `_gfortran_set_args(int, char **)`, `_gfortran_set_options(int, int *)`, and `MAIN__(void)` are visible (header include or forward decls) so the C compiles cleanly.
- Spot-check that no other call/side-effect inside `main` was lost beyond the stack-adjust artefact.
- Confirm the gfortran runtime version targeted matches the `set_options` flag value `7` (flag semantics are version-dependent).
