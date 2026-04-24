## init_iostream_globals @ 0x1810 — rewrite notes

### What the pipeline did
- Recognized the function as the **compiler-synthesized `_GLOBAL__sub_I_main` TU-constructor** that g++ emits whenever a translation unit includes `<iostream>`. The body is the textbook two-step pattern: construct the static `std::ios_base::Init` sentinel, then register its destructor with `__cxa_atexit`.
- Mapped the indirect call at `0x12d0` → `std::ios_base::Init::Init`, and the tail-jump at `0x1230` → `__cxa_atexit`.
- Interpreted the GOT-relative load `*&[var0+0x3ff8]` as the address of `std::ios_base::Init::~Init` passed as the first argument to `__cxa_atexit`.
- Cleaned up prologue/epilogue noise (`push/pop rbp`) and converted the tail-call `goto L_1230` into a normal call followed by an implicit return.
- Emitted C++ syntax (mangled-name expansions) despite the "c" target tag, since there is no pure-C equivalent for this construct.

### Assumptions not mechanically proven
- That `0x12d0` really is the `ios_base::Init` ctor PLT stub and `0x1230` really is `__cxa_atexit` — inferred from the pattern, not verified against the relocation/PLT table here.
- That the GOT slot at `rip+0x3ff8` holds `std::ios_base::Init::~Init` rather than some other cleanup function.
- That `_ZStL8__ioinit` is the standard libstdc++ sentinel (name matches, but not cross-checked against the symbol table in this note).
- Tail-call vs call+ret is treated as semantically equivalent (true for a void function with no further work, which is the case here).

### Reviewer checklist
