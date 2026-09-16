#include "runtime_sample.h"
typedef void(*fn)(void);int main(int argc,char **argv){if(!rs_bad(argc,argv))return rs_result("safe",1);volatile uintptr_t target=1;((fn)target)();return 0;}
