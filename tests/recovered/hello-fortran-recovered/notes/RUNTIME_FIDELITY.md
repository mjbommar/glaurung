# Runtime fidelity (Bug X partial closure)

The recovered Fortran tree compiles + links cleanly under
`gcc -O2 -Wall -Werror` and `-lgfortran`, but **SIGSEGVs at
runtime** when libgfortran walks the descriptor.

## What's verified

- **Compile**: every emitted `.c` builds clean under `-Wall -Werror`.
  Tests: `test_recover_source_externs.py` + `test_recover_source_fortran_main.py`.
- **Link**: every symbol resolves. `MAIN__` is preserved (Bug S),
  every `_gfortran_*` import has an extern (Bug Q), the binary's
  LOCAL statics (`options`, `subroutine_invocations`,
  `call_count_1`) get stub definitions (Bug W).
- **Descriptor offsets at the call boundary**: `flags+unit` at +0,
  `filename` at +0x08, `line` at +0x10 — matches what gfortran's
  own MAIN__ emits (Bug X partial).

## What's NOT verified

- **Runtime libgfortran I/O**: `_gfortran_st_write` reads private
  state from the descriptor at offsets we don't reproduce. The
  recovered tree's stack-allocated descriptor has zero-initialised
  private state (which libgfortran rejects as "uninitialised
  stream" on some code paths) and our `_pad[1004]` field doesn't
  match libgfortran's actual layout byte-for-byte.

## Why this is hard

libgfortran's `st_parameter_dt` has dozens of fields (iomsg /
iostat / format / namelist / advance / internal_unit / size / rec
/ iolength / private I/O state / pthread keys / …). The exact
layout varies between gcc 8, 10, 12, 13, and the version of
libgfortran the binary was originally linked against. A faithful
struct requires either:

1. Reading the gcc-source header for the targeted libgfortran
   version (`gcc/libgfortran/io/io.h`) and emitting an exact-match
   declaration, OR
2. Calling libgfortran's own `_gfortran_st_initialize_*` helpers
   (if they exist publicly) before each write.

Both are larger than this loop's scope.

## Resolution policy

- The build-and-link gate stays the regression watchdog (covered
  by 36 deterministic tests + the bench harness once Bug Y lands).
- Runtime fidelity is filed as the audit's still-open
  [high] confidence_gap finding from Bug L; closing it requires
  the libgfortran-version-aware ABI work above and the
  identify_compiler_and_runtime tool reporting libgfortran's
  declared version.
- Until then: **the recovered tree is faithful at the
  source-structure level, not at the runtime-execution level.**
  That's the right floor for an LLM-assisted rewriter; surpassing
  it is a v2 problem.
