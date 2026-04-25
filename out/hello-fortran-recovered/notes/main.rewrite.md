# main @ 0x10d0 — Rewrite Notes

## What the pipeline did
- Reconstructed the canonical gfortran `main` stub: `_gfortran_set_args(argc, argv)` → `_gfortran_set_options(7, options)` → `MAIN__()` → `return 0`.
- Restored the standard `int main(int argc, char **argv)` signature; pseudocode showed `_gfortran_set_args@plt()` with no visible args (likely passed via registers and not surfaced by the decompiler).
- Renamed the mangled static `options.6.2` to plain `options` for readability.
- Dropped non-semantic artefacts: the `rsp -= 8` stack-adjust and the explicit `ret = 0` temporary (folded into `return 0;`).
- Ignored unrelated ELF/dynamic-linker string literals seen in the binary dump.

## Assumptions not mechanically provable
- That `_gfortran_set_args` actually receives `(argc, argv)` here. This is the gfortran convention and almost certainly correct, but the pseudocode does not show the register moves that would confirm it.
- That `options.6.2` and `options` refer to the same symbol — true by gfortran naming convention but not verified against the symbol table in this note.
- That the constant `7` passed to `_gfortran_set_options` is a literal int (not a sentinel/array length tied to a different `options` definition). Standard gfortran emits this as the option-array length.

## Reviewer checklist
