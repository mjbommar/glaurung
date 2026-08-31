# hello_gfortran_O2

## What it is

`hello_gfortran_O2` is a small program recovered from a binary that was originally
compiled from Fortran source using `gfortran` at optimization level `-O2`. The
recovered sources presented here are in C: a thin `main.c` entry point that
bootstraps the Fortran runtime and invokes the original Fortran main program,
plus a `src/core.c` containing the remaining recovered functions that did not
fall into a more specific cluster.

Because the original was a Fortran program, the recovered C reflects the
calling conventions, runtime initialization, and helper routines that
`gfortran`-compiled binaries emit. This project is primarily useful as a
reference for what a minimal `-O2` `gfortran` "hello"-style program looks like
after recovery, and as a starting point for further reverse-engineering work.

## Building

The project uses CMake. From the project root:

```sh
cmake -B build
cmake --build build
```

This will configure a build tree under `build/` and produce the
`hello_gfortran_O2` executable.

## Running

The recovered program takes no required arguments:

```sh
./build/hello_gfortran_O2
```

Any options recognized by the original program are passed through on the
command line:

```sh
./build/hello_gfortran_O2 [OPTIONS]
```

See the manpage (section 1) for the documented synopsis.

## Module tour

- **`main.c`** — Program entry point. Provides the C `main` that bootstraps the
  Fortran runtime and dispatches into the original Fortran main program. This
  is the standard shape for a `gfortran`-built executable: the C-level `main`
  is a thin shim that initializes the runtime before calling the user's
  Fortran `PROGRAM`.
- **`src/core.c`** — Catch-all for unclustered recovered functions. Anything
  that did not naturally group into a more specific module ended up here.

## Notes on provenance

- Original language: Fortran
- Original compiler: gfortran
- Original optimization: `-O2`
- Recovered representation: C

Because the sources are recovered and lifted to C, names, control flow, and
function boundaries reflect the compiled artifact rather than the original
Fortran source.
