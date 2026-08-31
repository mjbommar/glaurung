# init_iostreams_global @ 0x1810 — Rewrite Notes

## What the pipeline did
- Recognized the symbol `_GLOBAL__sub_I_main` operating on `_ZStL8__ioinit` as the canonical libstdc++ static initializer emitted per TU that includes `<iostream>`, and rewrote it to the textbook two-call form: `std::ios_base::Init::Init(&_ZStL8__ioinit)` followed by `__cxa_atexit(~Init, &_ZStL8__ioinit, &__dso_handle)`.
- Mapped the indirect call to PLT slot `0x12d0` to the `Init` constructor, and the tail-jump to `L_1230` (argument shape `(fnptr, this, __dso_handle)`) to `__cxa_atexit`.
- Dropped the `nop`, `push rbp` / `pop rbp` frame scaffolding as semantically inert.
- Dropped the `*&[var0+0x3ff8]` load (stack-canary / `fs:0x28` residue) as a compiler artifact.

## Assumptions not mechanically proven
- `0x12d0` really resolves to `std::ios_base::Init::Init` (not, e.g., some other single-argument ctor/method on the same global). Only the symbol name + pattern support this.
- `0x1230` is `__cxa_atexit` (inferred from the 3-arg tail call with `__dso_handle`), not `__cxa_thread_atexit` or `atexit`.
- The first argument to the atexit registration is the `~Init` destructor. The pseudocode only shows `arg0 = *&[var0+0x3ff8]` being passed as `arg0` — the rewriter replaced this with the dtor pointer, which is inconsistent with the pseudocode as written (see checklist).
- `_ZStL8__ioinit` is the local (TU-private) `ios_base::Init` object, matching the `L` in the mangled name.

## Reviewer checklist
