int local_body(int a, int b) { return a * b + 7; }
int calls_local(int v) { return local_body(v, 3); }
double mix_float(double d, float f) { return d * 2.0 + (double)f; }
