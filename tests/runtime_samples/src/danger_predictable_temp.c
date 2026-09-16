#include "runtime_sample.h"
#include <fcntl.h>
int main(int argc,char **argv){char path[64];if(rs_bad(argc,argv))strcpy(path,"predictable.tmp");else snprintf(path,sizeof path,"safe-%ld.tmp",(long)getpid());int fd=open(path,O_CREAT|O_EXCL|O_WRONLY,0600);if(fd>=0){close(fd);unlink(path);}return rs_result("temp",fd>=0);}
