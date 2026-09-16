#include "runtime_sample.h"
int main(int argc,char **argv){(void)argc;(void)argv;const char *p=getenv("PATH");return rs_result("env",p!=NULL);}
