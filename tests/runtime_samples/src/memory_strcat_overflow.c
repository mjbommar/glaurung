#include "runtime_sample.h"
struct box{char dst[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{'A','B','C','\0'},0x55667788};strcat(b.dst,rs_bad(argc,argv)?"DEFGHIJK":"D");return rs_result("canary",b.canary);}
