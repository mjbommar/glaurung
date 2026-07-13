#include <stdlib.h>
__attribute__((noinline)) int leaf(int x){ return x*x + 1; }
__attribute__((noinline)) int (*pick(int s))(int){ return leaf; }
int compute(int n){
  int acc=0;
  int (*fp)(int) = pick(n);   /* forces an indirect BLR/BLRAA */
  for(int i=0;i<n;i++) acc += fp(i);
  return acc;
}
int main(int argc,char**argv){ return compute(argc)&0xff; }
