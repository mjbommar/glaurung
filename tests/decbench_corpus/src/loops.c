long sum_to(int n){ long s=0; for(int i=0;i<n;i++) s+=i; return s; }
long factorial(int n){ long f=1; while(n>1){ f*=n; n--; } return f; }
int count_bits(unsigned x){ int c=0; do { c += x&1; x>>=1; } while(x); return c; }
