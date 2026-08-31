# frame_dummy — review note

## What the pipeline did
- Recognized the pseudocode as the canonical GCC `frame_dummy` CRT stub: a `completed.0` guard followed by an indirect call through a JCR-table slot at `[rip + 0x3fe8]` (i.e., `__JCR_END__`/`_Jv_RegisterClasses`-style callback).
- Replaced the entire body with an **empty function definition**, on the assumption that this symbol is provided by `crtbegin.o`/`crtbeginS.o` and will be regenerated automatically when the rewritten source is relinked with a normal CRT.
- Renamed nothing; no local variables survive.

## Assumptions not mechanically provable
- That this binary's `frame_dummy` is the unmodified GCC stub and not a customized variant (e.g., one that calls a user-provided init hook). The pseudocode shape is consistent with the stock stub, but the indirect target at `var0+0x3fe8` is not resolved here.
- That the rebuilt artifact will be linked against a CRT that re-supplies `frame_dummy` / the JCR registration logic. If the rewrite is linked `-nostartfiles` or with a custom CRT, the dropped call disappears for real.
- That `completed.0` (the once-guard) is not observed by any other translated function. If some other rewritten function reads `completed`, dropping the store side-effect here breaks that.

## Divergences accepted
- Dropped indirect call through JCR slot (flagged low).
- Dropped read/update of `completed.0` guard (flagged low).

Both are acceptable **only** under the "stock GCC CRT" assumption above.

## Reviewer checklist
