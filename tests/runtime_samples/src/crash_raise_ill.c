#include "runtime_sample.h"
int main(int argc,char **argv){if(rs_bad(argc,argv))raise(SIGILL);return rs_result("safe",1);}
