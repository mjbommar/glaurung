#include "runtime_sample.h"
struct box{char dst[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x01020304};char src[16];memset(src,'N',sizeof src);memmove(b.dst,src,rs_bad(argc,argv)?12:8);return rs_result("canary",b.canary);}
