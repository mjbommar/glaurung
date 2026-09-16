#include "runtime_sample.h"
#include <dlfcn.h>
int main(int argc,char **argv){const char *p=rs_bad(argc,argv)?getenv("RUNTIME_SAMPLE_LIBRARY"):"libm.so.6";if(!p)p="untrusted.so";void *h=dlopen(p,RTLD_LAZY);if(h)dlclose(h);return rs_result("dlopen",h!=NULL);}
