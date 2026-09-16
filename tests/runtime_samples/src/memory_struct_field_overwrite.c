#include "runtime_sample.h"
struct box{unsigned char data[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x11223344};size_t i=rs_bad(argc,argv)?8:7;b.data[i]=0xaa;return rs_result("canary",b.canary);}
