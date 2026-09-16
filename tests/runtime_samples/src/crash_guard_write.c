#include "runtime_sample.h"
#include <sys/mman.h>
int main(int argc,char **argv){unsigned char *p=mmap(NULL,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);mprotect(p+4096,4096,PROT_NONE);if(!rs_bad(argc,argv)){munmap(p,8192);return rs_result("safe",1);}p[4096]=1;return 0;}
