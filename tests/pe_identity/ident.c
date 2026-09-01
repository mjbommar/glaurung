/* PE identity lane: local bodies, an import, and a thunk, at both bitnesses. */
int _fltused = 0;
__declspec(dllimport) int imported_helper(int);

__declspec(dllexport) int local_body(int a, int b) { return a * b + 7; }
__declspec(dllexport) int calls_import(int v) { return imported_helper(v) + 1; }
__declspec(dllexport) int calls_local(int v) { return local_body(v, 3); }
