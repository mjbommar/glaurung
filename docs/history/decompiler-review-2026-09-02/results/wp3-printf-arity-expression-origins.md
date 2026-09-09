# WP3 printf arity expression origins

Commit `6aa84209` closes one bounded expression-origin hole in variadic call
recovery. The format-proven arity recognizer now inspects the semantic payload
of an attributed call target and recursively unwraps attributed integer casts
around a literal format address. It retains the existing function whitelist,
format parser, architecture restriction, and fail-closed behavior.

The strengthened unit test first reproduced the defect: an origin-wrapped
`printf` target and origin-wrapped cast/address format source recovered only
one argument. With the change, it retains both the format and `%d` value.

Focused validation:

- exact regression: 1 passed;
- Rust tests selected by `printf`: 7 passed;
- exact-commit release build and native-extension build guard: fresh;
- `python/tests/test_open_decompiler_defects.py -k inlined_printf`: both test
  functions pass for their GCC and Clang fixture parameters.

No broad suite was run. The periodic Hello O2 sample was not repeated because
the immediately preceding WP3 increment already passed its x86-64, AArch64,
and ARMv7 cells; this change is confined to format-proven call arity.

This is not WP3 completion. Other expression consumers still require the same
semantic-payload and complete-origin audit, and universal production
attribution remains open.
