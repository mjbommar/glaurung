#include "runtime_sample.h"
#include <fcntl.h>
#include <sys/ioctl.h>
int main(int argc,char **argv){int fd=open("/dev/null",O_RDONLY);unsigned long request=rs_bad(argc,argv)?0xdeadbeefUL:0UL;int r=ioctl(fd,request,0);close(fd);return rs_result("ioctl",r);}
