# hello

A minimal C++ "hello" program recovered from the `hello-gcc-O2` build artifact
(originally compiled with GCC at `-O2`). It prints a greeting message and
exits.

This project is intentionally small — it exists primarily as a recovered
reference for the original binary, and as a starting point that can be built,
inspected, and extended.

## What it is

- A single-binary command-line program named `hello`.
- Written in C++ (recovered source; toolchain target is GCC).
- Builds with CMake.
- Has no runtime dependencies beyond the C++ standard library.

## Building

The project uses CMake. From the repository root:

```sh
cmake -B build
cmake --build build
```

This will produce a `hello` executable inside the `build/` directory.

If you want to match the original build flavor as closely as possible, you can
configure a release build with optimizations:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Running

After building, run the program directly:

```sh
./build/hello
```

The program accepts no required arguments; see the manpage for the supported
option set.

## Module tour

The source tree is intentionally tiny. Each translation unit has a single,
well-defined responsibility:

- `src/main.cpp` — Program entry point. Parses any options, then invokes the
  greeting routine implemented in `print_message.cpp`. This file is the place
  to wire in additional behavior or argument handling.
- `src/print_message.cpp` — Implements the hello/greeting message printing
  helper. The actual text emitted by `hello` lives here; modify this file to
  change what the program says.

## Notes on provenance

The sources in this repository were recovered from a GCC `-O2` build of the
original `hello` program. Because the inputs were optimized, identifiers,
control flow, and structure reflect a best-effort reconstruction rather than
the verbatim original source. Behavior, however, should match the recovered
binary.
