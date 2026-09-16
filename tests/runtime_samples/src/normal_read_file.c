#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){(void)argc;(void)argv;int fd=open("/dev/zero",O_RDONLY);char b[16];ssize_t n=read(fd,b,sizeof b);close(fd);return rs_result("read",n);}
