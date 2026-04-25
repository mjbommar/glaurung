# frame_dummy — Reviewer Note

## What the pipeline did
The rewriter recognized `frame_dummy` as a **GCC CRT-generated stub** (emitted from `crtbegin.o`) and replaced the entire decompiled body with an **empty function definition**. No locals were renamed and no logic was translated; the rewrite is purely a recognition-and-elision pass.

The dropped pseudocode is the canonical pattern:
- read `completed.0` guard, shift/test for prior execution
- read a function pointer at `var0 + 0x3fe8` (the legacy `__JCR_LIST__` / Java class registration callback slot)
- indirect-call it if non-null

## Assumptions not mechanically provable
1. That this function is genuinely compiler boilerplate and not a hand-written function that happens to resemble the GCC pattern.
2. That the toolchain re-emits an equivalent `frame_dummy` when this source is recompiled (true for GCC/Clang with standard CRT, but not guaranteed for exotic linker setups).
3. That `*(var0 + 0x3fe8)` really is the JCR table slot and not a project-specific callback the binary depends on.
4. That `completed.0` is the standard CRT guard (preventing double-execution) and has no other observers.

## Divergences (both flagged low)
- Indirect call through `*(var0+0x3fe8)` is dropped.
- `completed.0` guard read/update is dropped.

Both are acceptable **iff** the binary was built with a stock GCC CRT and the function is not referenced from user code.
