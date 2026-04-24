# Building `hello`

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The resulting binary is `build/hello`.

## Notes

* The recovered sources use a `.c` extension but their import list contains C++
  runtime symbols (`std::ostream`, `std::string`, `__cxa_*`, `__gxx_personality_v0`,
  `operator new`/`operator delete`). The CMake file compiles them as C++ and links
  via the C++ driver so `libstdc++` and `libgcc_s` are picked up automatically.
* `crt/crtstuff.c` is *not* built by default. On a normal Linux toolchain the real
  `crtstuff.o` is already linked in by GCC; building the recovered copy as well
  would produce duplicate `_ITM_deregisterTMCloneTable`, `_ITM_registerTMCloneTable`,
  `__cxa_finalize` stubs. Enable `-DHELLO_BUILD_CRTSTUFF=ON` only if you know you
  need it.
* `pthread` is linked because `__libc_start_main`-based binaries on glibc commonly
  pull it in and the recovered code may use thread-safe statics.
