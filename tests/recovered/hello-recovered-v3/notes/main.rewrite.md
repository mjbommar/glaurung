# Audit note — `main` @ 0x13d0

## What the pipeline did
- **Re-tagged language**: prototype said C, output is C++ because the binary uses libstdc++ (`std::vector<std::string>`, `std::cout`, mangled `HelloWorld::printMessage`).
- **Collapsed inlined std::string construction loop** (L_1553..L_15d0, with SSO vs heap branches at L_1530/L_1538/L_15ae) into `args.emplace_back(argv[i])`.
- **Collapsed 32-byte-stride length-accumulation loop** (L_15d0..L_15ed) into a range-for summing `s.size()`.
- **Inferred two `HelloWorld` instances** from the two `printMessage()` calls and matching ctor/dtor pairs.
- **Inferred `reserve(argc)`** from the `(span>>3)*32` allocation via `operator new` at 0x1250.
- **Dropped** duplicated basic-block tails (loop-peel artefacts), the stack-canary save/check, and the `__throw_length_error("cannot create std::vector larger than max_size()")` overflow path.
- **Renamed** locals semantically (`greeting`, `args`, `hello1`, `sum_label`) rather than via mechanical 1:1 substitution.

## Assumptions not mechanically provable
- Two distinct `HelloWorld` objects (vs one reused) — based on ctor/dtor pairing in prologue/epilogue.
- The `argv` copy is exactly `for i in [0,argc)` — argc bound came from `(cursor_span/8)` matching argv length convention.
- The accumulator `var8` is summing `string::size()` over `args` (not e.g. capacity).
- Second string literal decoded as `"Sum printer"` (11 bytes) from immediates 0x6e697270206d7553 / 0x6574 / 0x72 — note trailing `'r'` (0x72) wasn't shown in immediates table; verify.
- The single null-check throw maps to the `_M_construct null not valid` site only; original also chains to `__throw_length_error`.

## Known materially-different output (HIGH severity)
- **First greeting string**: leading 8 bytes come from `rodata[0x20a0]` in the binary; rewrite substitutes an empty-buffer placeholder. **Constructed string content is wrong.**
- **Counter value print**: original emits `stack_21` (untraced source); rewrite hard-codes `0`. **Observable output differs.**
- **Undefined identifiers** (`ERR_STRING_NULL_NOT_VALID`, `LBL_TOTAL_ARG_LENGTH`, `COUNTER_VALUE_LABEL`): code as written **will not compile**; literal strings from pseudocode were not inlined verbatim.
- **Dropped length_error path**: original calls `0x1270()` then `__throw_length_error`; rewrite throws a single `logic_error`.
