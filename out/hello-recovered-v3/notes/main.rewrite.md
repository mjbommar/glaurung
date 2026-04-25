# main @ 0x13d0 — Reviewer Note

## What the pipeline did
- **Language switch**: prototype said C, emitted C++ because the binary uses libstdc++ (`std::vector<std::string>`, `std::cout`, mangled `HelloWorld::printMessage`, ctor/dtor at 0x12a0/0x1260). Reasonable but worth confirming the project actually builds as C++.
- **Loop collapsing**: the inlined argv→`vector<string>` copy loop (SSO vs heap branches at L_1530/L_1538/L_1553/L_15ae) was rewritten as `reserve(argc)` + `emplace_back`. The 32-byte-stride length accumulation (L_15d0..L_15ed) became a range-for summing `s.size()`.
- **Two `HelloWorld` objects** (`hello1`, `hello2`) inferred from two printMessage calls and two ctor/dtor pairs.
- **Duplicate basic-block tails** (L_1508, L_1538-as-dup-of-L_1530, L_16a4 fallthrough dup) were dropped as loop-peel artefacts. Stack canary save/check dropped.
- **Error path consolidation**: original had three throw helpers (`0x1210` _M_construct null, `0x1270` length_error, `0x11f0` vector max_size); rewrite emits one `throw std::logic_error(...)` for the null case only.

## Assumptions that are NOT mechanically provable
- First `std::string` payload: leading 8 bytes come from `rodata[0x20a0]` which the pseudocode does not expose. **Rewrite substitutes an empty buffer placeholder** — constructed string is materially different from the original.
- "Counter value" source (`stack_21`) could not be traced; **hard-coded to `0`**, changing observable output.
- String literals replaced with **undefined symbolic identifiers** (`ERR_STRING_NULL_NOT_VALID`, `LBL_TOTAL_ARG_LENGTH`, `COUNTER_VALUE_LABEL`) — file will not compile as-is.
- `reserve(argc)` inferred from the `(span>>3)*32` allocation pattern; the explicit `> 0x1ffffffffffffff8` overflow check and its `length_error` throw are not reproduced.
- Two distinct `HelloWorld` instances (vs. one reused) is inferred from ctor/dtor pairing, not proven.
- `static_cast<size_t>(argc)` replaces a `movsxd`; equivalent only for non-negative argc.

## Reviewer checklist
