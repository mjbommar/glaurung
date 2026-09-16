#include "runtime_sample.h"
struct box{uint32_t a[4];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x13572468};size_t i=rs_bad(argc,argv)?4:3;b.a[i]=0xffffffff;return rs_result("canary",b.canary);}
