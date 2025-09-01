# Sample Source Files

This directory contains source code samples for building various binary formats for GLAURUNG analysis.

## Languages

### Native Compiled
- **C** (`c/hello.c`) - Standard C with functions, globals, static variables
- **C++** (`cpp/hello.cpp`) - C++ with classes, templates, STL usage
- **Fortran** (`fortran/hello.f90`) - Scientific computing example
- **Rust** (`rust/hello.rs`) - Memory-safe systems programming with traits, generics, threading
- **Go** (`go/hello.go`) - Concurrent programming with goroutines, channels, interfaces

### Bytecode/VM
- **Java** (`java/HelloWorld.java`) - JVM bytecode with classes and methods
- **C#** (`csharp/Hello.cs`) - .NET CLR with managed code
- **Python** (`python/hello.py`) - Python bytecode (.pyc) generation
- **Lua** (`lua/hello.lua`) - Lua bytecode with closures, coroutines, metatables

### Libraries
- **Shared/Dynamic** (`library/mathlib.c`) - Builds as .so, .dll, .dylib
- **Static** (`library/mathlib.c`) - Builds as .a, .lib
- **Test Program** (`library/test_mathlib.c`) - Tests library functionality

## Build Output Structure

```
binaries/
├── native/           # Native executables
│   ├── gcc/         # GCC builds (O0, O1, O2, O3, debug, stripped)
│   └── clang/       # Clang builds (O0, O1, O2, O3, debug, stripped)
├── cross/           # Cross-compiled binaries
│   ├── arm64/       # ARM 64-bit
│   ├── armhf/       # ARM 32-bit
│   ├── riscv64/     # RISC-V 64-bit
│   ├── x86_32/      # x86 32-bit
│   └── windows-x86_64/ # Windows PE files
├── fortran/         # Fortran builds
├── java/            # Java class files and JARs
│   ├── jdk11/
│   ├── jdk17/
│   └── jdk21/
├── dotnet/          # .NET assemblies
│   └── mono/
├── python/          # Python bytecode
├── lua/             # Lua bytecode (5.1, 5.2, 5.3, 5.4, LuaJIT)
├── go/              # Go binaries (standard, static, debug)
├── rust/            # Rust binaries (debug, release, musl)
├── libraries/       # Shared and static libraries
│   ├── shared/      # .so, .dll files
│   └── static/      # .a, .lib files
└── kernel-modules/  # Collected from host system
```

## Features Demonstrated

Each sample includes various language features to create interesting binaries for analysis:

- **Control Flow**: Loops, conditionals, function calls
- **Data Structures**: Arrays, structs, classes, maps/dictionaries
- **Concurrency**: Threads, goroutines, coroutines
- **Error Handling**: Exceptions, panic/recover, error returns
- **Dynamic Features**: Closures, callbacks, reflection
- **Optimization Targets**: Different optimization levels for analysis

## Building

Samples are built using Docker for reproducibility:

```bash
cd samples
./build-multiplatform.sh linux/amd64
```

This will compile all sources with various optimization levels and cross-compilation targets.