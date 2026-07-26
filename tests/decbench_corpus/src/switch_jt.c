int dispatch(int op, int a, int b){
  switch(op){ case 0:return a+b; case 1:return a-b; case 2:return a*b;
              case 3:return a&b; case 4:return a|b; case 5:return a^b;
              case 6:return a<<1; case 7:return b>>1; default:return -1; } }
