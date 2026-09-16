#include "runtime_sample.h"
#include <fcntl.h>
#include <sys/stat.h>
int main(int argc,char **argv){mode_t mode=rs_bad(argc,argv)?0666:0600;int fd=open("permissions.out",O_CREAT|O_TRUNC|O_WRONLY,mode);if(fd>=0)close(fd);chmod("permissions.out",mode);return rs_result("mode",mode);}
