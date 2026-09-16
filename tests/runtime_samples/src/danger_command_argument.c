#include "runtime_sample.h"
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?";id":"hello";printf("SINK command %s\n",p);return rs_result("metachar",strchr(p,';')!=NULL);}
