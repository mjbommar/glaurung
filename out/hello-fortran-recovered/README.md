# hello_fortran

A tiny "hello world" program recovered from a Fortran binary
(`hello-gfortran-O2`) and reconstructed as portable C source. The
original program was written in Fortran and compiled with `gfortran`
at `-O2`; this tree is a C-language re-expression of that program,
preserving the structure of a Fortran-style entry point.

## What it is

This project is a recovered C source tree corresponding to a small
Fortran program. Because Fortran programs compiled with `gfortran`
are launched through a small startup shim that calls the user's
`PROGRAM` body, the recovered code is split along the same seam:

- A C `main` that performs program startup and hands control to the
  translated Fortran program body.
- A separate C function that holds the body of the original Fortran
  `PROGRAM` (the "hello world" logic itself).

No runtime Fortran library dependency is implied by this tree — the
recovered code is plain C and builds with any C compiler.

## Building

The project uses CMake. From the project root:

```sh
cmake -B build
cmake --build build
```

This produces a `hello_fortran` executable inside the `build/`
directory.

## Running

Invoke the built binary directly:

```sh
./build/hello_fortran
```

The program takes no required arguments and prints its greeting to
standard output. See the manpage (`hello_fortran(1)`) for the full
invocation contract.

## Module tour

The source is intentionally minimal. Two translation units make up
the program:

### `main.c`
The C entry point. This corresponds to the startup glue that
`gfortran` would normally synthesize around a Fortran `PROGRAM`. It
performs whatever setup is required and then delegates to the
Fortran-style main program body defined in `hello.c`.

### `hello.c`
The body of the original Fortran program, translated into C. This
is where the actual "hello world" output happens — i.e., the work
that the Fortran `PROGRAM` block was performing in the original
source.

## Provenance

- Original artifact: `hello-gfortran-O2`
- Original language: Fortran
- Original compiler: `gfortran` (optimization level `-O2`)
- Recovered language: C
