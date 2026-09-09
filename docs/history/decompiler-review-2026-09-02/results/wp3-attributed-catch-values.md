# WP3 attributed catch values

Commit `d5d3b8dd` closes the two O0 execution failures exposed by the exception
constant-fold checkpoint. The recovered catch body read the result of
`__cxa_begin_catch` through an expression-origin carrier. Exception recovery
recognized only bare register copies and bare dereferences, so it failed to
replace that machine pointer load with the typed `catch (int exception_0)`
binding. The generated standalone program then dereferenced an uninitialized
`rax_call_lifetime_*` value and crashed on `INT_MIN`.

Direct caught-pointer aliases are now origin-transparent. An attributed
four-byte load becomes the typed catch binding, and the replacement retains the
deterministic union of the consumed load and address owners. This is a bounded
WP3 consumer migration, not completion of authoritative SSA or the broader
exception pipeline.

## Focused evidence

The new contract was observed red first with the attributed dereference still
present. After the repair:

```text
cargo test --features python-ext --lib \
  ir::exception_recover::tests::typed_handler_tracks_attributed_caught_pointer_values
1 passed; 4,740 filtered out
```

The owning module ran 11 tests: the new contract and nine other tests passed.
`aarch64_got_typeinfo_sequence_retains_the_int_throw_proof` failed, and the
same exact test also fails on clean pushed parent `826571a8`; it is unrelated
existing assertion debt rather than evidence against this change.

An exact detached release build of `d5d3b8dd` produced native SHA-256
`5b26f88fa919027754f829500f60de732c6215de15005290fb633310a2a007cc`.
The directly owning execution differential is fully green:

```text
10_cpp_runtime_shapes:clang:O0:cpp_exception  pass
10_cpp_runtime_shapes:clang:O2:cpp_exception  pass
10_cpp_runtime_shapes:gcc:O0:cpp_exception    pass
10_cpp_runtime_shapes:gcc:O2:cpp_exception    pass
```

The GCC O0 catch path now reads `exception_0`; it no longer declares or
dereferences the invalid catch-side call-lifetime pointer. No broad Rust,
Python, fixture, architecture, DecBench, or Joern suite ran.
