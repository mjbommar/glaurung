// src/iostream_support.c
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Inserts a newline character into an output stream and flushes it.
 *
 * Standard library manipulator equivalent to `std::endl`. Obtains the
 * `std::ctype<char>` facet from the stream's imbued locale (cached in the
 * stream's ctype slot) and uses it to widen `'\n'` to the stream's character
 * type, then writes the resulting character via `__os.put()` and flushes the
 * stream with `__os.flush()`.
 *
 * The widen operation is performed via the facet's fast-path cache
 * (`_M_widen`) when initialized (`_M_widen_ok`). Otherwise `_M_widen_init()`
 * is called; if the facet's vtable entry for `do_widen` points at the base
 * `ctype<char>::do_widen`, `'\n'` is used directly, else `do_widen('\n')`
 * is invoked.
 *
 * @param __os Output stream to write the newline to and flush.
 * @return Reference to @p __os after the newline has been written and the
 *         stream has been flushed.
 *
 * @note Throws `std::bad_cast` (via `std::__throw_bad_cast()`) if the stream
 *       has no `ctype<char>` facet installed (facet pointer is null).
 *
 * @code
 *   std::cout << "hello" << std::endl;  // writes '\n' and flushes
 * @endcode
 */
std::ostream &std::endl(std::ostream &__os)
{
    typedef std::ctype<char> ctype_t;
    std::basic_ios<char> &ios = __os;
    std::locale::facet *fac = ios._M_streambuf_state; /* ctype facet slot */

    if (fac == nullptr) {
        std::__throw_bad_cast();
    }

    char nl;
    if (static_cast<ctype_t *>(fac)->_M_widen_ok) {
        nl = static_cast<ctype_t *>(fac)->_M_widen['\n'];
    } else {
        static_cast<ctype_t *>(fac)->_M_widen_init();
        if (*(void **)fac /* vtable */ ->do_widen == &ctype_t::do_widen) {
            nl = '\n';
        } else {
            nl = static_cast<ctype_t *>(fac)->do_widen('\n');
        }
    }

    __os.put(nl);
    return __os.flush();
}

/**
 * @brief Static initializer for the C++ iostream library in this translation unit.
 *
 * Compiler-generated global sub-initializer (name-mangled as
 * `_GLOBAL__sub_I_main`) emitted for any translation unit that includes
 * `<iostream>`. It constructs the file-scope `std::ios_base::Init` sentinel
 * object `_ZStL8__ioinit`, which guarantees that the standard streams
 * (`std::cin`, `std::cout`, `std::cerr`, `std::clog`, and their wide
 * counterparts) are fully constructed before any user code in this TU runs.
 *
 * It then registers `std::ios_base::Init::~Init` with `__cxa_atexit`, bound
 * to the same `_ZStL8__ioinit` instance and the current shared object's
 * `__dso_handle`, so the sentinel is destroyed at program/library shutdown
 * in the correct order.
 *
 * This function is invoked automatically by the C++ runtime (via the
 * `.init_array` / `.ctors` mechanism) before `main()`; it is never called
 * directly from user code.
 *
 * @return None. Has no parameters and no return value.
 *
 * @note The referenced symbols are standard ABI artifacts:
 *       - `_ZStL8__ioinit` — the TU-local `std::ios_base::Init` object.
 *       - `__dso_handle`  — the per-DSO handle used by `__cxa_atexit`.
 * @note Safe against multiple TUs: `std::ios_base::Init` uses an internal
 *       reference count so only the first construction performs real work.
 */
static void _GLOBAL__sub_I_main(void)
{
    std::ios_base::Init::Init(&_ZStL8__ioinit);
    __cxa_atexit(std::ios_base::Init::~Init, &_ZStL8__ioinit, &__dso_handle);
}

