# stream_endl @ 0x1930 — Review Note

## What the pipeline did

- Recognised the function as libstdc++'s `std::endl<char>` (the `.isra.0` clone of `_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_`) after `widen()` was inlined.
- Walked the vtable-offset-`-0x18` trick to identify the `basic_ios` → `ios_base` subobject and treated the pointer at `+0xF0` as the `ctype<char>` facet.
- Named the `+0x38` field `_M_widen_ok` and the cached table at `+0x39..` `_M_widen`, inferred from the `movsx` byte load.
- Identified `0x1290` as `ctype<char>::_M_widen_init`, `0x12b0` as `std::__throw_bad_cast`, and `0x11b0` as an `ostream` helper.
- Target language was requested as C but rewritten as C++ (reasonable — no `std::ostream` in C). Stack/register shuffling was dropped as ABI noise.

## Assumptions not mechanically provable

- That the null-facet branch calls `__throw_bad_cast` (noreturn). The pseudocode still shows a `return arg1` fallthrough afterwards.
- That `0x11b0` is specifically `ostream::put` AND that an additional `flush()` belongs here. The pseudocode contains exactly **one** tail call to `0x11b0` per path; the rewrite emits both `put(nl)` and `flush()`.
- That the fast identity path passes the widened char at all — the `L_195c` site calls `0x11b0(rbp)` with only the ostream in `rbp`, no visible char argument.
- The facet-pointer field was labelled `_M_streambuf_state`, which is the wrong `ios_base` member name for offset `+0xF0`.

## Known bad code

- The `*(void **)fac ->do_widen == &ctype_t::do_widen` expression is not valid C++ and does not faithfully reproduce the vtable-slot `+0x30` load and compare against the register-held function pointer (`arg2` in pseudocode).

## Likely net effect

An extra `flush()` call and/or a wrong-arity `put()` call may have been synthesised. Semantically `std::endl` does `put('\n'); flush();` so the *intent* matches the standard, but it may not match *this binary's* actual call sequence (which may be a single combined helper, or only `put`, with flush elsewhere).
