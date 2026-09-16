#include "runtime_sample.h"
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?getenv("PATH"):"/usr/bin";if(!p)p="";printf("SINK search_path %s\n",p);return rs_result("path_len",(long)strlen(p));}
