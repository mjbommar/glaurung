#include "runtime_sample.h"
struct box{char dst[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x1234abcd};int p[2];pipe(p);write(p[1],"abcdefghijkl",12);rs_checkpoint_if("GLAURUNG_RUNTIME_CHECKPOINT_BEFORE_READ");read(p[0],b.dst,rs_bad(argc,argv)?12:8);close(p[0]);close(p[1]);return rs_result("canary",b.canary);}
