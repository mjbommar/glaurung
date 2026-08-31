# hello

A small "Hello, world" style program recovered from the `hello-gcc-O2` binary
(originally written in C++, compiled with gcc at `-O2`). This repository
contains the reconstructed source and a minimal build system suitable for
inspection, rebuilding, and experimentation.

## What it is

`hello` is a command-line program whose job is to print a greeting message
and exit. It is intentionally minimal: a single translation unit
(`src/hello.cpp`) holds the program entry point together with a small helper
responsible for emitting the greeting.

Because the source was recovered from an optimized binary, the code is
structured to reproduce the observable behavior of the original program
rather than to be an idiomatic from-scratch implementation. Treat this
repository as a faithful reconstruction, not a reference design.

## Requirements

- A C++ toolchain (the original was built with gcc; any reasonably modern
  C++ compiler should work).
- CMake.

## Building

The project uses CMake. From the repository root:

```sh
cmake -B build
cmake --build build
```

This produces a `hello` executable inside the `build/` directory.

## Running

Once built, run the executable directly:

```sh
./build/hello
```

The program accepts the general option form shown in the synopsis
(`hello [OPTIONS]`), but in normal use it is invoked with no arguments and
simply prints its greeting to standard output before exiting.

## Module tour

The source tree is small. The interesting file is:

- **`src/hello.cpp`** — Hello-world program entry point and message printing
  helper. This file contains `main` (the entry point invoked by the C
  runtime) and a small helper used by `main` to print the greeting message.
  All program logic lives here.

The CMake build glues this single source file into the final `hello`
executable; there are no other modules, libraries, or external
dependencies.

## Notes for developers

- The project was recovered from an optimized (`-O2`) gcc build, so some
  control flow in the reconstructed source may reflect compiler
  transformations (inlining, tail calls, etc.) rather than the original
  hand-written structure.
- If you want to compare against the original binary, build with the same
  compiler and optimization level (`gcc -O2`) for the closest match.
- See the `hello(1)` manpage in this repository for a brief command-line
  reference.
