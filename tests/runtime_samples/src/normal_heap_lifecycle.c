#include "runtime_sample.h"
int main(int argc,char **argv){size_t n=rs_bad(argc,argv)?128:32;unsigned char *p=calloc(n,1);if(!p)return 2;p[n-1]=7;long v=p[n-1];free(p);return rs_result("heap",v);}
