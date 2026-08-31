# hello

A small "hello"-style program whose source was recovered from the ELF binary
`hello-gcc-O2`. Although the recovered sources are organized as C files, the
binary was originally linked against the C++ standard library (it uses
`std::vector<std::string>` and the iostreams machinery), so the recovered
project contains helpers that mirror that runtime behavior.

This repository is intended as a reference for developers studying the
binary or rebuilding an equivalent executable. Treat the sources as a
faithful reconstruction rather than pristine upstream code.

## What it is

`hello` is a command-line program that prints a top-level message and
exits. The recovered code is split across a handful of translation units
that reflect what the compiler emitted and what the C runtime contributed:

- Program entry and the actual message-printing logic.
- A destructor helper for a `std::vector<std::string>` that appeared in
  the original object code.
- Small iostream support shims (stream newline / `std::endl`, ctype
  widening, iostream global initialization).
- The usual CRT startup/shutdown glue pulled in from `crtstuff.c`.

## Building

The project uses CMake. From the top of the source tree:

```sh
cmake -B build
cmake --build build
```

This will configure into a `build/` directory and produce the `hello`
executable there.

## Running

Invoke the program directly:

```sh
./build/hello
```

The program accepts no required arguments. See the manpage
(`hello(1)`) for the full synopsis:

```
hello [OPTIONS]
```

## Module tour

- **`src/main.c`** — Program entry point and top-level message-printing
  logic. This is where execution begins after CRT startup hands control
  over to the program.
- **`src/vector_string.c`** — Destructor helper for
  `std::vector<std::string>`. Recovered from code the C++ compiler
  emitted to tear down a vector-of-strings object.
- **`src/iostream_support.c`** — C++ iostream helpers: stream newline /
  `std::endl` support and ctype widening, plus iostream global
  initialization (the machinery that ensures `std::cout` and friends are
  constructed before `main` runs and destroyed afterward).
- **`crt/crtstuff.c`** — CRT-provided constructor/destructor glue and
  the program startup stub. This is the standard `crtstuff`
  scaffolding the toolchain links in; it is reproduced here because it
  appears in the recovered binary.

## Notes for developers

- Because the sources were recovered from an optimized build
  (`-O2`), the structure reflects what the optimizer and linker
  produced rather than hand-written layout. Expect small helper
  functions and split responsibilities that would normally live in the
  C++ standard library.
- The iostream and vector helpers are present because the original
  binary used C++ I/O and containers; if you port the program to pure
  C, those modules can be dropped in favor of `printf`.
