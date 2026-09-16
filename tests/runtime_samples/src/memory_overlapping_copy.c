#include "runtime_sample.h"
int main(int argc,char **argv){char b[16]="abcdefghijk";if(rs_bad(argc,argv))memcpy(b+1,b,8);else memmove(b+1,b,8);return rs_result("overlap",b[2]);}
