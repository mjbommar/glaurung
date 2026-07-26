void matmul(const int *A,const int *B,int *C,int n){
  for(int i=0;i<n;i++) for(int j=0;j<n;j++){ int s=0;
    for(int k=0;k<n;k++) s+=A[i*n+k]*B[k*n+j]; C[i*n+j]=s; } }
