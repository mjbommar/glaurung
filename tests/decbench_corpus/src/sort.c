void bubble(int *a,int n){ for(int i=0;i<n;i++) for(int j=0;j<n-1-i;j++)
    if(a[j]>a[j+1]){ int t=a[j];a[j]=a[j+1];a[j+1]=t; } }
int bsearch_i(const int *a,int n,int key){ int lo=0,hi=n-1;
  while(lo<=hi){ int m=(lo+hi)/2; if(a[m]==key)return m; if(a[m]<key)lo=m+1; else hi=m-1; } return -1; }
