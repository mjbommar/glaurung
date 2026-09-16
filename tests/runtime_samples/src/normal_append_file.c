#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){(void)argc;(void)argv;int fd=open("append.txt",O_CREAT|O_APPEND|O_WRONLY,0600);ssize_t n=write(fd,"x",1);close(fd);return rs_result("append",n);}
