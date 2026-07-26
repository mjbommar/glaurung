int sum_array(const int *a, int n){ int s=0; for(int i=0;i<n;i++) s+=a[i]; return s; }
int max_array(const int *a,int n){ int m=a[0]; for(int i=1;i<n;i++) if(a[i]>m)m=a[i]; return m; }
void reverse(int *a,int n){ for(int i=0,j=n-1;i<j;i++,j--){ int t=a[i];a[i]=a[j];a[j]=t; } }
