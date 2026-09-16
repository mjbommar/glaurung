#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){(void)argc;(void)argv;int fd=open("written.bin",O_CREAT|O_TRUNC|O_WRONLY,0600);ssize_t n=write(fd,"glaurung",8);close(fd);return rs_result("written",n);}
