/* Keep the two calls real without adding an unresolved dependency or another
 * exported function to the shared execution-matrix fixture. */
static __attribute__((noinline)) long selected_step(long value) {
    return value + 3;
}

static __attribute__((noinline)) long record_selected_value(long *out, long value) {
    __asm__ volatile("" : : "r"(out), "r"(value) : "memory");
    return value;
}

/* A lazy call-valued select. Optimized machine code initializes the surviving
 * value with x and overwrites it only on the nonzero edge; the decompiler must
 * retain both source value edges rather than rendering a one-sided update. */
void guarded_call_select(long x, long *out) {
    long value = x ? selected_step(x) : 0;
    value = record_selected_value(out, value);
    out[0] = value;
}
