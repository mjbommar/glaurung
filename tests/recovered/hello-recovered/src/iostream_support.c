// src/iostream_support.c
// Recovered from hello-gcc-O2 by glaurung source-recovery
//
// Bug EE: this file originally tried to recover the body of
// `std::endl` and the per-TU `_GLOBAL__sub_I_main` static
// initializer that constructs `_ZStL8__ioinit`. Both are
// libstdc++-internal artefacts and were emitted as raw C++
// syntax (`std::ostream`, `std::ctype<char>`, `_M_widen_init()`,
// etc.) without including the headers they came from, so the
// translation unit refused to compile.
//
// The recovered tree doesn't need either function:
//
// * `std::endl` is a header-only template; main.c gets its
//   own copy by including <iostream>.
// * The static initializer for std::cout / std::cerr is
//   provided by libstdc++'s own crtstuff when the binary
//   links against -lstdc++.
//
// Gutting the file to a minimal empty TU lets the build-gate
// pass without losing functionality. The original speculation
// is preserved in git history.

/* Intentionally empty translation unit — see header comment. */
