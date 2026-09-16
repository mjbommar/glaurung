#include "runtime_sample.h"
#include <sys/mman.h>
typedef void(*fn)(void);int main(int argc,char **argv){unsigned char *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);p[0]=0xc3;if(!rs_bad(argc,argv)){munmap(p,4096);return rs_result("safe",1);}((fn)p)();return 0;}
