/* PDB type/layout recovery fixture. Freestanding: /nodefaultlib. */
/* The CRT normally defines these; /nodefaultlib means we must.
 * _fltused is emitted as a reference by any TU using float/double. */
int _fltused = 0;
struct Point { int x; int y; };
struct Record { unsigned char tag; int value; struct Point origin; };

__declspec(dllexport) int point_sum(struct Point p) { return p.x + p.y; }
__declspec(dllexport) int record_value(struct Record *r) { return r->value + r->origin.x; }
__declspec(dllexport) int scale_pair(int a, short b, char c) { return a * b + c; }
__declspec(dllexport) double mix_float(double d, float f) { return d * 2.0 + (double)f; }
__declspec(dllexport) unsigned long long widen(unsigned int v) { return (unsigned long long)v << 8; }
