__attribute__((noinline)) int classify(int n) {
    if (n < 0) {
        return -1;
    }
    while (n > 100) {
        n -= 100;
    }
    return n;
}
