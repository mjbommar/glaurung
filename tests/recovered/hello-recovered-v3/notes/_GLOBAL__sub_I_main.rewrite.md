# Audit note: `_GLOBAL__sub_I_main` @ 0x1810

## What the pipeline did
- Recognized the function as the **standard libstdc++ static initializer** emitted for TUs that include `<iostream>`. Replaced the raw indirect calls with their canonical names:
  - `0x12d0(rbp)` → `std::ios_base::Init::Init(&_ZStL8__ioinit)`
  - tail-call to `0x1230` → `__cxa_atexit(&~Init, &_ZStL8__ioinit, &__dso_handle)`
- **Dropped prologue/epilogue noise**: `push rbp`, `pop rbp`, and the `*&[var0+0x3ff8]` load were treated as stack-canary / frame-pointer artefacts and not represented in the source.
- **Argument reconstruction at the tail-call** was inferred from register conventions (rbp→arg1, `__dso_handle`→arg2); the third register (`arg0`) was assumed to be the destructor function pointer even though pseudocode shows it loaded from `[var0+0x3ff8]`, not from a known symbol.
- **Language mix**: emitted C++ syntax (`std::ios_base::Init::Init`) inside a file targeting C, on the grounds that the mangled ABI cannot be expressed in pure C cleanly.

## Assumptions not mechanically provable
- That `0x12d0` is the `Init` ctor and `0x1230` is `__cxa_atexit` — based purely on the canonical pattern, not verified against the actual call targets in the binary.
- That `*&[var0+0x3ff8]` is unrelated to the logic (treated as canary/GOT noise). It could equally be the **destructor function pointer loaded from the GOT**, which would still be correct in spirit but means arg0 is *not* a stack canary.
- That the function has no other side effects and the omitted prologue/epilogue are truly inert.
- That `_ZStL8__ioinit` is the `std::ios_base::Init` object (name suggests so, but type/size unverified).

## Notes
- Verification step reported "LLM unavailable; equivalence could not be checked" — no automated cross-check was performed.
- Target language was C but output uses C++ syntax; downstream build config must accommodate this.
