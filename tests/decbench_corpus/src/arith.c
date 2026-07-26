long addmul(long a, long b, long c) { return a * b + c - (a ^ b); }
unsigned shifts(unsigned x, int n) { return (x << n) | (x >> (32 - n)); }
int signs(int a, int b) { return (a < 0 ? -a : a) + (b > a ? b - a : a - b); }
