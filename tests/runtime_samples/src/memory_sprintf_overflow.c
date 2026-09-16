#include "runtime_sample.h"
struct box{char dst[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x66778899};sprintf(b.dst,"%s",rs_bad(argc,argv)?"0123456789AB":"ok");return rs_result("canary",b.canary);}
