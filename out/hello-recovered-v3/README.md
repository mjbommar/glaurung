# hello

Recovered C++ project. Despite the `.cpp` source extension, the requested
target language was C; however the binary clearly links against the C++
standard library (libstdc++), so the build is configured as C++.

## Build

```sh
cmake -S . -B build
cmake --build build
```

The resulting executable is `build/hello`.
