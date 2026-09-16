#include "runtime_sample.h"
int main(int argc,char **argv){unsigned char *p=calloc(1,16);uint32_t *c=(uint32_t *)(p+8);*c=0x12345678;size_t i=rs_bad(argc,argv)?8:7;p[i]=0xff;long v=*c;free(p);return rs_result("canary",v);}
