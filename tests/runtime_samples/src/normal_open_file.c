#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?"missing-runtime-sample":"input.txt";int fd=open(p,O_RDONLY);if(fd<0)return rs_result("open_errno",errno);close(fd);return rs_result("open_ok",1);}
