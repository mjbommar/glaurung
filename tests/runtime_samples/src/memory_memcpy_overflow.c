#include "runtime_sample.h"
struct box{char dst[8];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x10203040};char src[16];memset(src,'M',sizeof src);rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");memcpy(b.dst,src,rs_bad(argc,argv)?12:8);rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");return rs_result("canary",b.canary);}
