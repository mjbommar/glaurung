int fp_mul(int a,int b){ return (int)(((long)a*b)>>16); }
int fp_div(int a,int b){ return (int)(((long)a<<16)/b); }
int isqrt(long n){ long x=n, y=(x+1)/2; while(y<x){ x=y; y=(x+n/x)/2; } return (int)x; }
