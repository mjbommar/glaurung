# Rewrite notes — `_GLOBAL__sub_I_main` @ 0x1810

*Target language: c*

## Assumptions

- This is the standard libstdc++ global static initializer emitted for any TU that includes <iostream>; the call at 0x12d0 is std::ios_base::Init::Init() on _ZStL8__ioinit and the tail-call at 0x1230 is __cxa_atexit registering the matching destructor.
- The stack-canary load (*(canary+0x3ff8)) and rbp save/restore are compiler-emitted prologue/epilogue artefacts and have been omitted from the rewritten source.
- The variable renames stack_canary/frame_ptr/dso_handle describe register usage at the tail-call boundary, not user-visible arguments; only __dso_handle survives into the source as the third argument to __cxa_atexit.
- String-literal renames (ELF_MAGIC_STR, LD_LINUX_X86_64_PATH, etc.) belong to other sections of the binary and are not referenced by this constructor; they were ignored.
- Mixed C/C++ symbols (std::ios_base::Init) are written in C++ syntax even though the requested target language is C, because the underlying ABI calls cannot be expressed in pure C without name-mangled extern declarations.

## Divergences flagged

- [low] other: LLM unavailable; equivalence could not be checked

## Reviewer TODO

- [ ] verify: This is the standard libstdc++ global static initializer emitted for any TU that
- [ ] verify: The stack-canary load (*(canary+0x3ff8)) and rbp save/restore are compiler-emitt
- [ ] verify: The variable renames stack_canary/frame_ptr/dso_handle describe register usage a
- [ ] verify: String-literal renames (ELF_MAGIC_STR, LD_LINUX_X86_64_PATH, etc.) belong to oth
- [ ] verify: Mixed C/C++ symbols (std::ios_base::Init) are written in C++ syntax even though 
- [ ] resolve divergence: [low] other: LLM unavailable; equivalence could not be checked