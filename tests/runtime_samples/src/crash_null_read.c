#include "runtime_sample.h"
int main(int argc,char **argv){if(!rs_bad(argc,argv))return rs_result("safe",1);volatile int *p=(int *)0;return *p;}
