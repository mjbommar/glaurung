# hello_gfortran_O2

A small recovered project originally written in Fortran and compiled with
`gfortran` at optimization level `-O2`. The recovered sources in this tree are
C — specifically a thin entry-point shim (`main.c`) responsible for
bootstrapping the Fortran runtime and handing control to the Fortran main
program.

This README is aimed at developers who want to build, run, and explore the
project.

---

## What it is

`hello_gfortran_O2` is the recovered form of a program produced from Fortran
source compiled with `gfortran -O2`. Recovery preserves the structure of the
original `gfortran`-built binary, including the conventional split between:

- the C-style program entry point (`main`), and
- the Fortran main program invoked from it.

In practice this means the project behaves like a standard `gfortran`-linked
executable: process startup runs through a small C entry point that initializes
the GNU Fortran runtime (libgfortran) and then dispatches to the Fortran
`MAIN__` routine.

The project is intentionally minimal — there are no command-line features
beyond what the Fortran runtime itself provides.

## Requirements

- A C toolchain (any C compiler that can build the recovered `main.c`).
- CMake (used as the build driver).
- The GNU Fortran runtime library (`libgfortran`) available at link/run time,
  since the original program was produced with `gfortran`.

## Building

The project uses CMake. From the project root:

```sh
cmake -B build
cmake --build build
```

This will configure an out-of-tree build under `build/` and produce the
`hello_gfortran_O2` executable inside that directory.

## Running

Once built, run the executable directly:

```sh
./build/hello_gfortran_O2
```

The program accepts no application-specific options. Any options recognized
are those handled by the underlying Fortran runtime.

## Module tour

The project is small. The notable file is:

- **`main.c`** — Program entry point. Bootstraps the Fortran runtime and
  dispatches to the Fortran main program. This is the `main` symbol the linker
  uses to start the process; the actual user-level logic of the original
  program lived in the Fortran main program that this shim invokes.

## Notes on recovery fidelity

Because the binary was built with `gfortran -O2`, some recovered structure
reflects compiler-introduced glue (runtime initialization, name mangling of
the Fortran main program, etc.) rather than user-authored code. Treat the
recovered C as a faithful skeleton of what the toolchain produced, not as the
original Fortran source.

## See also

- `hello_gfortran_O2(1)` manpage in this repository.
- `gfortran(1)`, `libgfortran` documentation.
