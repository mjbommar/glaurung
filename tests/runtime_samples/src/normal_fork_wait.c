#include "runtime_sample.h"
#include <sys/wait.h>
int main(int argc,char **argv){(void)argc;(void)argv;pid_t p=fork();if(p<0)return 2;if(p==0)_exit(7);int st=0;waitpid(p,&st,0);return rs_result("child",WEXITSTATUS(st));}
