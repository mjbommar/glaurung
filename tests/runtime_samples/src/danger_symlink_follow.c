#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?"link-input":"regular-input";int fd=open(p,O_RDONLY|O_CREAT,0600);if(fd>=0)close(fd);return rs_result("follow",fd>=0);}
