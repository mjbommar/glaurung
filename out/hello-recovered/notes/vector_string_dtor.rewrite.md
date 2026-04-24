## vector_string_dtor @ 0x1a50 — Rewrite Notes

**What the pipeline did**
- Recognized the function as `std::vector<std::__cxx11::string>::~vector()` (D2 base dtor) and renamed it `std__vector_string__dtor` with a `this` parameter.
- Collapsed two duplicated compare-and-branch blocks (L_1a70 head + fall-through) into a single `for (p = first; p != last; ++p)` loop. The rewriter flagged this as an optimizer artefact; semantically equivalent iff `first != last` on entry (which is the only path that reaches those blocks).
- Interpreted the inner `stack_top == rbp+16` test as the libstdc++ SSO check `p->_M_dataplus._M_p != &p->_M_local_buf` and emitted a conditional `operator_delete` for heap-allocated strings.
- Hard-coded the 32-byte element stride as `sizeof(std::__cxx11::basic_string<char>)`.
- Mapped offsets 0/8/16 on `this` to `_M_start` / `_M_finish` / `_M_end_of_storage`.
- Dropped prologue/epilogue callee-saved push/pop pairs as noise.
- Emitted the sized two-arg `operator delete` for the backing store and the unsized form for per-element SSO buffers, even though both calls in the pseudocode go to the same PLT stub (0x1260).

**Unprovable assumptions**
- `0x1260` is `operator delete` (both sized and unsized forms). Not verified against the PLT/relocation table.
- Object layout: 32-byte `std::string`, SSO buffer at offset 16, vector triple at 0/8/16. Only true for a specific libstdc++ ABI/build; not mechanically checked.
- The two `0x1260` calls actually take different argument shapes (sized vs. unsized). The pseudocode shows both with similar stack setup — the sized-vs-unsized split in the rewrite is a guess.
- Collapsing the duplicated loop heads assumes no observable side effect from the redundant compare.

**Reviewer checklist**
