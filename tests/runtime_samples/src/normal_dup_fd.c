#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){(void)argc;(void)argv;int fd=open("/dev/null",O_WRONLY);int copy=dup(fd);int ok=write(copy,"x",1);close(copy);close(fd);return rs_result("dup",ok);}
