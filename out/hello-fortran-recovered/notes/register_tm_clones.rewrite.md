## register_tm_clones @ 0x1160 — review note

### What the pipeline did
- Recognised the function as the **standard GCC CRT `register_tm_clones` stub** (paired with `deregister_tm_clones`, emitted alongside `_init`/`_fini`).
- **Replaced the entire body with an empty function**, discarding:
  - The `(__TMC_END__ - __TMC_LIST__) / sizeof(ptr) >> 1` size computation.
  - The conditional indirect call through GOT slot `[rip+0x3fe8]` (canonically `_ITM_registerTMCloneTable`).
- Renamed/dropped the artefact locals (`completed.0`, the duplicated `arg0`/`arg1`/`ret`) since they have no use in the empty form.
- No assumptions about external symbols are encoded — the stub is treated as boilerplate.

### Assumptions that are not mechanically provable
- The binary is a normal C/C++ executable where `_ITM_registerTMCloneTable` is **not** provided by any TM runtime, so the GOT slot is NULL and the indirect call never fires at runtime.
- The function is compiler-emitted CRT glue and not user-authored code that happens to look like it.
- The rebuild toolchain (GCC/clang) will re-emit an equivalent stub, so dropping the source body is link-time safe.

### Known divergences (both flagged low)
- `dropped_call`: indirect dispatch to `_ITM_registerTMCloneTable` is omitted. Silently a no-op in standard links; behaviour-changing if a TM runtime is linked in.
- `control_flow`: size==0 and NULL-pointer guards are gone; equivalent only under the above assumption.

### Reviewer checklist
