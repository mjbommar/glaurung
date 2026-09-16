#include "runtime_sample.h"
#include <assert.h>
int main(int argc,char **argv){assert(!rs_bad(argc,argv));return rs_result("safe",1);}
