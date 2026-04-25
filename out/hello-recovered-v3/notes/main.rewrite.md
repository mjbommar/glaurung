# Audit note — `main` @ 0x13d0

## What the pipeline did
- **Language switch**: prototype declared C, but the rewriter emitted C++ because the binary uses libstdc++ (`std::vector<std::string>`, `std::cout`, mangled `HelloWorld::printMessage`, ctor/dtor pairs). Reasonable, but worth confirming the build system is OK with this.
- **Loop collapsing**:
  - Inlined argv→`std::vector<std::string>` copy loop (SSO + heap branches at L_1530/L_1538/L_1553/L_15ae) replaced by `reserve(argc) + emplace_back`.
  - 32-byte-stride length accumulator (L_15d0..L_15ed) replaced by a `range-for` summing `s.size()`.
- **Object identity**: inferred two distinct `HelloWorld` instances (`hello1`, `hello2`) from two ctor/dtor/printMessage triples.
- **Renames**: role-based (`greeting`, `args`, `sum_label`, `total_length`) rather than mechanical, because pseudocode names collide across scopes.
- **Error paths consolidated**: original had three throw sites (`basic_string::_M_construct null not valid`, `__throw_length_error`, `cannot create std::vector larger than max_size()`). Rewriter kept only a single null-arg check throwing a `logic_error`, dropping the length_error and vector-max-size paths.
- **Dropped**: stack canary save/check, duplicated basic-block tails (loop-peel artefacts).

## Assumptions not mechanically provable
- **rodata[0x20a0] is unrecoverable** → first `std::string`'s leading 8 bytes substituted with an empty placeholder. **Materially changes the constructed string.**
- **`stack_21` (counter value) source not traced** → hard-coded `0`. **Changes observable output.**
- Used **undefined symbolic identifiers** (`ERR_STRING_NULL_NOT_VALID`, `LBL_TOTAL_ARG_LENGTH`, `COUNTER_VALUE_LABEL`) where the pseudocode has actual string literals. **Code as-emitted will not compile** and the observable strings differ from the binary.
- Assumed `argc >= 0` so `static_cast<size_t>(argc)` is equivalent to the original `movsxd`.
- Assumed `reserve(argc)` matches the original's direct `operator new(argc*32)` semantics — fine at source level, but skips the explicit `> 0x1ffffffffffffff8` overflow check.
- Assumed the two `printMessage` calls are on distinct objects rather than one re-used object.

## Reviewer checklist
