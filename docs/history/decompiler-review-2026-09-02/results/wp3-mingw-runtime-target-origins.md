# WP3 MinGW runtime-target expression origins

Commit `4b03122e` makes MinGW's implicit `__main`/`___main` source-cleanup rule
transparent to expression ownership on the direct callee. Provenance no longer
causes the compiler-inserted runtime initialization call to leak into recovered
`main` source.

The deletion policy remains narrow: the enclosing function must be `main` or
`_main`; the statement must be a result-free, argument-free direct call; and
the semantic callee must be exactly `__main` or `___main`. The deleted call's
statement or expression origins are not reassigned to neighboring source
statements.

The existing ownership test was strengthened by attributing the `___main`
target itself. It was observed red before production repair with three
statements retained instead of two. After repair:

```text
attributed_mingw_runtime_call_is_deleted_without_reassigning_its_owner: 1 passed
mingw_implicit_main_runtime_call_is_not_emitted_as_source:              1 passed
mingw_:                                                                4 passed
```

An exact detached release build of `4b03122e` was fresh. The directly owning
real PE32 test passes:

```text
python/tests/test_pe32_cdecl_roundtrip.py::
  test_real_mingw32_main_has_bounded_cdecl_arguments: pass
```

No broad Rust, Python, fixture, DecBench, or Joern suite ran. The periodic
six-cell Hello checkpoint was not repeated because it passed at exact commit
`bf8718e9` immediately before these call-target increments.

This closes one bounded x86/PE expression consumer, not WP3. Authoritative SSA
identity, explicit invalidation, and the remaining semantic-consumer audit stay
open.
