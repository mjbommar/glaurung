#include "runtime_sample.h"
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?"user-%x-%x":"user-ok";printf("SINK format %s\n",p);return rs_result("percent",strchr(p,'%')!=NULL);}
