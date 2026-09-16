#include "runtime_sample.h"
#include <sys/mman.h>
int main(int argc,char **argv){(void)argc;(void)argv;unsigned char *p=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 2;p[0]=42;long v=p[0];munmap(p,4096);return rs_result("mmap",v);}
