#include "runtime_sample.h"
#include <sys/mman.h>
int main(int argc,char **argv){unsigned char *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);p[0]=1;mprotect(p,4096,PROT_READ);if(!rs_bad(argc,argv)){munmap(p,4096);return rs_result("safe",1);}p[0]=2;return 0;}
