## `_GLOBAL__sub_I_main` @ 0x1810 — rewrite notes

**What the pipeline did**
- Recognised this as the canonical libstdc++ per-TU static initializer for `<iostream>` and rewrote it as the idiomatic two-call form: `std::ios_base::Init::Init(&_ZStL8__ioinit)` followed by `__cxa_atexit(dtor, &_ZStL8__ioinit, &__dso_handle)`.
- Dropped prologue/epilogue artefacts: the `push rbp` / `pop rbp` pair and the `*(fs:0x28)`-style canary load (shown in the pseudocode as `*&[var0+0x3ff8]`) were treated as compiler-emitted noise and not represented in source.
- Resolved the indirect call at `0x12d0` to the `Init` ctor and the tail-`jmp` at `0x1230` to `__cxa_atexit`; the tail-call register setup (rdi=ctor object, rsi unused→reused, rdx=`__dso_handle`) was reinterpreted as the `(func, arg, dso)` argument triple.
- Emitted C++ symbol syntax despite the requested C target (assumption #5).

**Assumptions that are not mechanically provable**
- That `0x12d0` is a PLT/thunk for `std::ios_base::Init::Init` and `0x1230` is the PLT for `__cxa_atexit`. Neither was confirmed by the verifier (LLM-equivalence check was unavailable — see flagged divergence).
- That the destructor passed to `__cxa_atexit` is `std::ios_base::Init::~Init`. The pseudocode does not show how the first argument to the tail-call is loaded, so the dtor identity is inferred purely from the libstdc++ idiom.
- That the `[var0+0x3ff8]` load is a stack canary rather than a meaningful value flowing into the tail call. If it actually feeds `rdi`/`rsi` of the tail call, the reconstruction is wrong.
- That `rbp` (= `&_ZStL8__ioinit`) is the second argument to `__cxa_atexit`; the pseudocode only shows `arg1 = rbp` symbolically.

**Divergences**
- Low: equivalence check skipped (LLM unavailable). No positive confirmation that the rewrite matches the original.
