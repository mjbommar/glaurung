#include "runtime_sample.h"
int main(int argc,char **argv){int written=7;if(rs_bad(argc,argv))printf("ABCD%n",&written);else printf("ABCD");putchar('\n');return rs_result("written",written);}
