#include "runtime_sample.h"
int main(int argc,char **argv){volatile unsigned char *p=malloc(16);p[0]=1;if(rs_bad(argc,argv)){free((void *)p);p[0]=9;return rs_result("stale",p[0]);}long v=p[0];free((void *)p);return rs_result("safe",v);}
