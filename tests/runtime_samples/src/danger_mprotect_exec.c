#include "runtime_sample.h"
#include <sys/mman.h>
int main(int argc,char **argv){void *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);int prot=PROT_READ|(rs_bad(argc,argv)?PROT_EXEC:0);int r=mprotect(p,4096,prot);rs_checkpoint();munmap(p,4096);return rs_result("mprotect",r);}
