#include "runtime_sample.h"
#include <sys/wait.h>
int main(int argc,char **argv){int count=rs_bad(argc,argv)?3:1;int made=0;for(int i=0;i<count;i++){pid_t p=fork();if(p==0){rs_checkpoint();_exit(0);}if(p>0)made++;}while(wait(NULL)>0){}return rs_result("children",made);}
