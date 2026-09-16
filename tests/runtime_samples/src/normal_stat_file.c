#include "runtime_sample.h"
#include <sys/stat.h>
int main(int argc,char **argv){struct stat st;const char *p=rs_bad(argc,argv)?"missing":"/dev/null";int r=stat(p,&st);return rs_result("stat",r==0?(long)st.st_mode:-errno);}
