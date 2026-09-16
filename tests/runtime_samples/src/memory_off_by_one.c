#include "runtime_sample.h"
struct box{char text[8];unsigned char tag;};int main(int argc,char **argv){struct box b={{0},0x5a};size_t n=rs_bad(argc,argv)?8:7;memset(b.text,'A',n);b.text[n]='\0';return rs_result("tag",b.tag);}
