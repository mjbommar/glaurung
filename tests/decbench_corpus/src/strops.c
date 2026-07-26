int str_len(const char *s){ int n=0; while(s[n]) n++; return n; }
int str_cmp(const char *a,const char *b){ while(*a&&*a==*b){a++;b++;} return *a-*b; }
unsigned hash_djb2(const char *s){ unsigned h=5381; int c; while((c=*s++)) h=((h<<5)+h)+c; return h; }
