long fib(int n){ if(n<2) return n; return fib(n-1)+fib(n-2); }
long ackermann(long m,long n){ if(m==0)return n+1; if(n==0)return ackermann(m-1,1);
  return ackermann(m-1, ackermann(m,n-1)); }
