#include "runtime_sample.h"
int main(int argc,char **argv){(void)argc;(void)argv;int p[2];char c=0;if(pipe(p))return 2;write(p[1],"Q",1);read(p[0],&c,1);close(p[0]);close(p[1]);return rs_result("pipe",c);}
