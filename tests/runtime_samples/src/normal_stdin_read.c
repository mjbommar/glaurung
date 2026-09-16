#include "runtime_sample.h"
int main(int argc,char **argv){(void)argc;(void)argv;char b[8];ssize_t n=read(STDIN_FILENO,b,sizeof b);return rs_result("stdin",n);}
