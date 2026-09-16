#include "runtime_sample.h"
int main(int argc,char **argv){return rs_result("argc",rs_bad(argc,argv)?argc+10:argc);}
