#include "runtime_sample.h"
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?"../../etc/passwd":"safe/input.txt";printf("SINK path %s\n",p);return rs_result("path",strstr(p,"..")!=NULL);}
