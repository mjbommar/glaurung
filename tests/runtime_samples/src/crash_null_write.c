#include "runtime_sample.h"
int main(int argc,char **argv){
#ifdef GLAURUNG_RUNTIME_COUNTERFACTUAL_CRASH_FIXTURE
rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");if((unsigned char)argv[1][0]!='b'){rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");return rs_result("safe",1);}
#else
if(!rs_bad(argc,argv))return rs_result("safe",1);
#endif
volatile int *p=(int *)0;*p=7;return 0;}
