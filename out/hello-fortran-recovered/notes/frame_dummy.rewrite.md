## frame_dummy @ 0x11e0 — Reviewer Note

### What the pipeline did
- **Wholesale replacement**: The decompiled body (subtraction of `completed.0` from itself, right shifts, GOT load at `var0+0x3fe8`, conditional indirect call) was discarded and replaced with a single `register_tm_clones();` call.
- **Renamed**: Function labeled `sub_11e0` in the binary, but the rewriter used the semantic name `frame_dummy` based on the standard CRT layout.
- **Dropped dead control flow**: The trailing `goto L_1160` after `return` (likely a decompiler artifact / alignment nop) was not represented.
- **Added comment** documenting that this is compiler-generated CRT glue.

### Assumptions not mechanically provable
- The inlined arithmetic + GOT-indirect call really is `register_tm_clones` (the rewriter recognized the well-known glibc CRT idiom by shape, not by symbol resolution).
- The GOT slot at `var0+0x3fe8` actually holds the `__cxa_finalize`/deregistration pointer that `register_tm_clones` checks — not verified against the binary's relocations.
- A symbol named `register_tm_clones` exists (or will be linked) in the project. If the rebuild is freestanding, this call may not resolve.
- `frame_dummy` is the correct semantic name (vs. some other CRT stub at this address).

### Behavioral note
The original is the *inlined* form (-O2); the rewrite is the *un-inlined* C source. These compile to equivalent code only if the compiler chooses to inline `register_tm_clones` again. For a CRT stub this is essentially always benign.

### Reviewer checklist
- Confirm address 0x11e0 corresponds to `frame_dummy` in the binary's symbol table / `.init_array`.
- Confirm a separate `register_tm_clones` function exists in the recovered project (or is provided by CRT) so this call links.
- Verify the offset `0x3fe8` from the PIC base matches the `register_tm_clones` GOT check, not some unrelated indirect call.
- Confirm `frame_dummy` is referenced from `.init_array` (or equivalent) — if not, this stub may be dead and the rename is misleading.
- Decide whether to keep CRT stubs in the recovered source at all, or let the toolchain regenerate them (often preferable).
- Sanity-check that no observable behavior depended on the dropped `goto L_1160` / nop tail (should be none).