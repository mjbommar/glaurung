#include "runtime_sample.h"
#include <sys/mman.h>
int main(int argc,char **argv){int prot=PROT_READ|PROT_WRITE|(rs_bad(argc,argv)?PROT_EXEC:0);void *p=mmap(NULL,4096,prot,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 2;memset(p,0,16);rs_checkpoint();munmap(p,4096);return rs_result("rwx",(prot&PROT_EXEC)!=0);}
