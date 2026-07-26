int classify(int a,int b){ if(a>b) return a-b; else if(a<b) return b-a; return 0; }
int nested(int x,int y,int z){ if(x){ if(y) return z; else return -z; } return 0; }
