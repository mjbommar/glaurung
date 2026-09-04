# WP8 declared-call pointer-boundary evidence

Date: 2026-09-04

## Defect

The real `locale_name_length` fixture had authoritative libc declarations and
correct pointer-typed locals, but rendered these calls:

```c
saved_locale = (char *)(strdup((long)old_locale));
length = strlen((long)saved_locale);
free((long)saved_locale);
```

GCC rejected all three arguments under `-Werror`. Two renderer decisions caused
the loss: a return-type spelling difference could replace a trusted declaration
with the recovered whole-call carrier, and the call-argument printer consulted
incoming-pointer hints instead of the declaration plan's selected type for a
recovered local.

## Change

Implementation commit: `d8acf6aa9a4a6c676e76b3976c6f19d7dde6a708`.
Base revision: `38cb69131b67bf9fd565eb6e79fdb3e10e7fe58b`.

`src/ir/ast/dec_render.rs` now:

- decides whether a direct call needs a site-owned function-pointer cast from
  parameter compatibility only, leaving return/destination adaptation to the
  existing statement-level result conversion;
- renders a register as a pointer at a call boundary when the declaration plan
  selected any pointer type for it, including recovered locals; and
- removes one pointer-width integer transport cast only when the inner
  expression is already proven compatible with the consuming pointer type.

`src/ir/ast.rs` contains a focused regression test with a PLT-decorated
`strdup` target, an authoritative `char * (const char *)` declaration, and a
different recovered return carrier. The test requires `strdup(arg0)` and valid
C. The existing incomplete-call test continues to require a site-owned cast
when parameter arity is incompatible.

Two stale real-fixture assertions were aligned with already-authoritative
output: DWARF restores `candidate` rather than `arg0`, and pointer declarators
use the repository's current `FILE *arg0` spacing. The generated test census
moved by exactly one declaration: total `4273 -> 4274`, Rust IR `2030 -> 2031`.

## RED and GREEN evidence

Before the production change:

```text
cargo test --features python-ext \
  declared_pointer_call_keeps_parameter_types_when_result_needs_conversion \
  --lib -- --nocapture

FAILED
saved_locale = ((long (*)(long))strdup)(old_locale);
```

After the production change:

```text
cargo test --features python-ext \
  declared_pointer_call_keeps_parameter_types_when_result_needs_conversion --lib -q
1 passed; 0 failed

cargo test --features python-ext \
  incomplete_call_keeps_authoritative_declaration_and_owns_a_site_cast --lib -q
1 passed; 0 failed

cargo test --features python-ext call --lib
372 passed; 0 failed
```

The native extension was rebuilt after the Rust edit with
`uv run maturin develop`. Python validation then used `uv run --no-sync` so
`uv` could not replace the freshly built extension with a cached project wheel.

```text
/usr/bin/time -v uv run --no-sync pytest \
  python/tests/test_libc_pointer_roundtrip.py -q
3 passed; 0 failed
wall time 0.78 s; maximum RSS 99,760 KiB

uv run --no-sync pytest -q \
  python/tests/test_test_census.py python/tests/test_libc_pointer_roundtrip.py
9 passed; 0 failed

/usr/bin/time -v uv run --no-sync python tools/dectest.py @smoke
4 scoped lanes of 838; no scoped regressions
wall time 2.69 s; maximum RSS 120,612 KiB
```

The nullable-locale fixture is the one improved cell. It now renders direct
`strdup(old_locale)`, `strlen(saved_locale)`, and `free(saved_locale)` calls,
recompiles under the fixture's strict flags, and matches the original program's
output. The direct-string and stripped-FILE fixtures are unchanged semantically
and also recompile and execute equivalently. This increment changes no
`goto`, `switch`, `case`, or `break` count.

## Broad gates and limitations

```text
cargo test --features python-ext
3,786 library tests passed; 4 ignored; all ordinary integration targets passed;
2 doc tests passed; 1 ignored
```

The mandated structural command did not yield structural evidence:

```text
uv run --no-sync pytest python/tests/test_decompiler_fixture_structural.py -xvs
interrupted after 276.89 s; no tests ran
```

Its session fixture was blocked in
`structural_report -> decompile_all -> subprocess.run -> communicate` after the
decompiler child process was no longer present. This is an infrastructure hang,
not a green or red structural result.

The def-use census passed its first three checks and failed the new-finding
ratchet on 21 current-tip functions, the same broad drift class already
recorded by the preceding WP8 increment. The new libc fixture is not part of
that census. No def-use baseline was edited.

The required post-commit whole Python command was started:

```text
uv run pytest python/tests/ -q --tb=short
interrupted at 19 percent after the active decompiler child disappeared
```

The parent stopped in
`test_decompiler_determinism.py::test_two_renders_in_one_process_are_identical`
inside `diff_decompile.decompiled_c -> subprocess.run -> communicate`. Process
inspection showed only pytest's sleeping queue-management threads and the
multiprocessing forkserver/resource tracker; no worker remained capable of
producing a result. The partial run was already broadly red on current-master
expectation and semantic failures, including analyst-local initializers,
obsolete pointer spacing, build-configuration improvement ratchets, ARM32
round trips, control-flow cases, and both def-use ratchets. It is not a
completed or green whole-suite result.

GED, type-match, byte-match, and Union metrics were not evaluated for this
bounded fixture repair, so no score movement is claimed.
