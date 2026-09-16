#include "runtime_sample.h"
int main(int argc,char **argv){size_t n=rs_bad(argc,argv)?64*1024*1024:4096;void *p=malloc(n);long ok=p!=NULL;free(p);return rs_result("allocation",ok);}
