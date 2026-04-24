// src/vector_string.c
// Recovered from hello-gcc-O2 by glaurung source-recovery

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Base destructor (D2) for `std::vector<std::string>`.
 *
 * Destroys every `std::string` currently stored in the range
 * `[_M_start, _M_finish)`, then releases the vector's underlying storage.
 *
 * For each element, the small-string-optimisation (SSO) state is inspected:
 * if `_M_dataplus._M_p` does not point at the element's inline `_M_local_buf`,
 * the heap-allocated character buffer is freed via `operator delete`.
 * After all elements have been destroyed, if `_M_start` is non-NULL the
 * storage block of size `_M_end_of_storage - _M_start` bytes is freed via
 * the sized `operator delete`.
 *
 * @param this Pointer to the `std::vector<std::string>` instance to destroy.
 *             Must reference a valid (possibly empty) vector; `_M_start` may
 *             be NULL for a default-constructed / moved-from vector, in which
 *             case no deallocation is performed.
 *
 * @note This is the D2 (base) destructor; it does not invoke any virtual
 *       destructor chain and does not free the `std::vector` object itself.
 * @note Elements whose string data lives in the inline `_M_local_buf` (SSO)
 *       require no heap free; only out-of-line buffers are released.
 */
/* std::vector<std::string>::~vector() - base destructor (D2) */
void std__vector_string__dtor(std__vector_string *this)
{
    std__string *first = this->_M_start;
    std__string *last  = this->_M_finish;

    /* Destroy each std::string in [first, last). */
    for (std__string *p = first; p != last; ++p) {
        /* If the string's _M_dataplus._M_p does not point at the inline
         * _M_local_buf, the heap buffer must be freed via operator delete. */
        if (p->_M_dataplus._M_p != p->_M_local_buf) {
            operator_delete(p->_M_dataplus._M_p);
        }
    }

    /* Deallocate the vector's storage. */
    if (this->_M_start != NULL) {
        operator_delete(this->_M_start,
                        (char *)this->_M_end_of_storage - (char *)this->_M_start);
    }
}

