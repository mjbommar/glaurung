## main @ 0x13d0 — rewrite audit

### What the pipeline did
- Recognized the function as C++ `main` despite the "C" target request, and kept C++ stdlib constructs (`std::vector<std::string>`, `std::cout`, `HelloWorld`) because the symbol table requires them. File is C++-in-C-style comments.
- Collapsed the compiler-peeled loops (L_1508 vs its fall-through, L_1672 vs its predecessor, L_15e0 self-loop) into single `for` loops.
- Replaced libstdc++'s SSO `_M_construct` dispatch (small ≤15 / medium =1 / large branches with offsets +16/+8, stride 32) with a plain `push_back(std::string(argv[i]))`.
- Replaced the pointer-walk over argv (`stack_top = argv + argc<<3`, `var4 == stack_top`) with a count-based `for (i < argc)` loop.
- Replaced the size-summation loop (stride 32, reading SSO length at offset +8) with `args[i].size()` accumulation.
- Dropped compiler artefacts: stack canary save/check, register shuffles, explicit RAII destructors (`~vector`, `~HelloWorld`, allocator deallocate), and the throw landing pads (`basic_string::_M_construct null not valid`, `cannot create std::vector larger than max_size()`).
- Used `reserve(argc)` to approximate the original single `operator new(argc*32)` allocation.

### Assumptions that are NOT mechanically provable
- **String literal is a placeholder.** The rewriter invented `"Sum printed C+ +!"` for the `HelloWorld` ctor argument. Actual bytes come from `.rodata+0x20a0` + immediates `0x2b43206d` ("m C+") and `0x212b` ("+!"), forming a 0x16-byte string that was not dumped.
- **Second string construction folded away.** Pseudocode clearly builds a *second* `std::string` (length 0xB, bytes "Sum prin"/"te", literal `stack_15=114` i.e. 'r') right before the second `printMessage()`. The rewrite merges it into the first greeter — one whole construction is gone.
- **Second `printMessage()` call dropped.** The pseudocode calls `_ZN10HelloWorld12printMessageEv` twice; rewrite calls it once.
- **`counter` hard-coded to 0.** `stack_21` is printed but its initialization/update site isn't in the visible slice. Could be nonzero at runtime.
- `reserve + push_back` is assumed equivalent to the original single bulk allocation + in-place construction — allocation/move behaviour may differ.
- argv null-entry throw path is assumed to be preserved implicitly by `std::string(char*)`'s own null check.

### Reviewer checklist
