#include "runtime_sample.h"
#include <sys/resource.h>
typedef int(*recur_fn)(volatile int);
RS_NOINLINE static int recurse(volatile int n);
static recur_fn volatile next_recurse=recurse;
RS_NOINLINE static int recurse(volatile int n){volatile char pad[4096];pad[n&7]=(char)n;return pad[n&7]+next_recurse(n+1);}int main(int argc,char **argv){if(!rs_bad(argc,argv))return rs_result("safe",1);struct rlimit limit={262144,262144};if(setrlimit(RLIMIT_STACK,&limit))return 2;return recurse(1);}
