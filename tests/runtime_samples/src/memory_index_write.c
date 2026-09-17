#include "runtime_sample.h"
struct box{uint32_t a[4];uint32_t canary;};int main(int argc,char **argv){struct box b={{0},0x13572468};size_t i;
#ifdef GLAURUNG_RUNTIME_COUNTERFACTUAL_SINK_FIXTURE
rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");i=(unsigned char)argv[1][0]=='b'?4:3;
#else
i=rs_bad(argc,argv)?4:3;rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
#endif
b.a[i]=0xffffffff;rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");return rs_result("canary",b.canary);}
