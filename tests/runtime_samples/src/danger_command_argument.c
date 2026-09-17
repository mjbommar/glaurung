#include "runtime_sample.h"
#ifdef GLAURUNG_RUNTIME_INDIRECT_TARGET_FIXTURE
__attribute__((noinline)) static int indirect_safe(void){return 17;}
__attribute__((noinline)) static int indirect_other(void){return 23;}
#endif
int main(int argc,char **argv){char command[6];volatile char *observed_command=command;volatile unsigned char mirror;memcpy(command,rs_bad(argc,argv)?";id-x":"hel-x",sizeof command);rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_BEGIN");
#ifdef GLAURUNG_RUNTIME_INDIRECT_TARGET_FIXTURE
int (*volatile observed_target)(void)=((unsigned char)argv[1][0]=='b')?indirect_other:indirect_safe;
mirror^=(unsigned char)observed_target();
#endif
#ifdef GLAURUNG_RUNTIME_COUNTERFACTUAL_SINK_FIXTURE
if((unsigned char)argv[1][0]=='b')command[0]=';';else command[0]='h';
#endif
#ifdef GLAURUNG_RUNTIME_COUNTERFACTUAL_UNSAT_FIXTURE
volatile unsigned char unsat_probe=(unsigned char)argv[1][0];
if(unsat_probe!='c')mirror=3;
if(unsat_probe=='c')mirror=4;else mirror=5;
#endif
#ifdef GLAURUNG_RUNTIME_COUNTERFACTUAL_PROFILE_FIXTURE
volatile unsigned char profile_probe=(unsigned char)argv[1][0];
if(profile_probe=='b')mirror=6;else mirror=7;
if(profile_probe=='c')mirror=8;else mirror=9;
if(profile_probe!='c')mirror=10;else mirror=11;
if(profile_probe<='c')mirror=12;else mirror=13;
#endif
#ifdef GLAURUNG_RUNTIME_REPLAY_UNSUPPORTED_FIXTURE
__asm__ volatile("smsw %ax");
#endif
#ifdef GLAURUNG_RUNTIME_REPLAY_BRANCH_FIXTURE
volatile unsigned char branch_probe=(unsigned char)argv[1][0];
#ifdef GLAURUNG_RUNTIME_REPLAY_SYMBOLIC_POINTER_FIXTURE
mirror^=(unsigned char)observed_command[branch_probe&1];
#endif
if(branch_probe=='b')mirror=1;else mirror=2;
#endif
command[4]=argv[1][0];mirror=(unsigned char)observed_command[4];rs_checkpoint_if("GLAURUNG_RUNTIME_TRACE_END");printf("SINK command %s\n",command);return rs_result("metachar",strchr(command,';')!=NULL)+(mirror==0xff);}
