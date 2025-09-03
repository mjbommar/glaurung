#ifdef _WIN32
#include <windows.h>

// Simple TLS callback to exercise TLS directory parsing.
static void NTAPI tls_callback(PVOID h, DWORD reason, PVOID res) {
    // Do nothing; just ensure presence for analysis
    volatile DWORD sink = reason;
    (void)h; (void)res; (void)sink;
}

#ifdef __GNUC__
// Place the callback pointer into the CRT TLS callbacks section for MinGW/GCC
PIMAGE_TLS_CALLBACK p_tls_callback __attribute__((section(".CRT$XLB"), used)) = tls_callback;
#else
#pragma constseg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;
#pragma constseg()
#endif

int main(void) {
    return 0;
}
#else
int main(void) { return 0; }
#endif

