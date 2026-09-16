#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){(void)argc;(void)argv;int fd=open("created.txt",O_CREAT|O_TRUNC|O_WRONLY,0600);if(fd<0)return 2;write(fd,"ok",2);close(fd);return rs_result("created",2);}
