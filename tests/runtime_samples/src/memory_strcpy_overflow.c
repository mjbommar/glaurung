#include "runtime_sample.h"
struct box{char dst[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x11223344};strcpy(b.dst,rs_bad(argc,argv)?"ABCDEFGHIJK":"ABC");return rs_result("canary",b.canary);}
