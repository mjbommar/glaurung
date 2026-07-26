#!/usr/bin/env python3
"""Emit a small, diverse corpus of self-contained C programs for decompiler
validation. Each is freestanding (no libc calls in the functions under test, so
cross-target `-c` objects link/analyze cleanly) and exercises a distinct
control-flow / data shape. Ground-truth source lives beside each object."""
import os
from pathlib import Path

SRC = Path(__file__).parent / "src"
SRC.mkdir(parents=True, exist_ok=True)

PROGRAMS = {
"arith": r"""
long addmul(long a, long b, long c) { return a * b + c - (a ^ b); }
unsigned shifts(unsigned x, int n) { return (x << n) | (x >> (32 - n)); }
int signs(int a, int b) { return (a < 0 ? -a : a) + (b > a ? b - a : a - b); }
""",
"loops": r"""
long sum_to(int n){ long s=0; for(int i=0;i<n;i++) s+=i; return s; }
long factorial(int n){ long f=1; while(n>1){ f*=n; n--; } return f; }
int count_bits(unsigned x){ int c=0; do { c += x&1; x>>=1; } while(x); return c; }
""",
"branches": r"""
int classify(int a,int b){ if(a>b) return a-b; else if(a<b) return b-a; return 0; }
int nested(int x,int y,int z){ if(x){ if(y) return z; else return -z; } return 0; }
""",
"switch_jt": r"""
int dispatch(int op, int a, int b){
  switch(op){ case 0:return a+b; case 1:return a-b; case 2:return a*b;
              case 3:return a&b; case 4:return a|b; case 5:return a^b;
              case 6:return a<<1; case 7:return b>>1; default:return -1; } }
""",
"recursion": r"""
long fib(int n){ if(n<2) return n; return fib(n-1)+fib(n-2); }
long ackermann(long m,long n){ if(m==0)return n+1; if(n==0)return ackermann(m-1,1);
  return ackermann(m-1, ackermann(m,n-1)); }
""",
"arrays": r"""
int sum_array(const int *a, int n){ int s=0; for(int i=0;i<n;i++) s+=a[i]; return s; }
int max_array(const int *a,int n){ int m=a[0]; for(int i=1;i<n;i++) if(a[i]>m)m=a[i]; return m; }
void reverse(int *a,int n){ for(int i=0,j=n-1;i<j;i++,j--){ int t=a[i];a[i]=a[j];a[j]=t; } }
""",
"matrix": r"""
void matmul(const int *A,const int *B,int *C,int n){
  for(int i=0;i<n;i++) for(int j=0;j<n;j++){ int s=0;
    for(int k=0;k<n;k++) s+=A[i*n+k]*B[k*n+j]; C[i*n+j]=s; } }
""",
"strops": r"""
int str_len(const char *s){ int n=0; while(s[n]) n++; return n; }
int str_cmp(const char *a,const char *b){ while(*a&&*a==*b){a++;b++;} return *a-*b; }
unsigned hash_djb2(const char *s){ unsigned h=5381; int c; while((c=*s++)) h=((h<<5)+h)+c; return h; }
""",
"sort": r"""
void bubble(int *a,int n){ for(int i=0;i<n;i++) for(int j=0;j<n-1-i;j++)
    if(a[j]>a[j+1]){ int t=a[j];a[j]=a[j+1];a[j+1]=t; } }
int bsearch_i(const int *a,int n,int key){ int lo=0,hi=n-1;
  while(lo<=hi){ int m=(lo+hi)/2; if(a[m]==key)return m; if(a[m]<key)lo=m+1; else hi=m-1; } return -1; }
""",
"structs": r"""
struct pt { int x, y; };
long dist2(struct pt a, struct pt b){ long dx=a.x-b.x, dy=a.y-b.y; return dx*dx+dy*dy; }
int rect_area(const struct pt *p){ return (p[1].x-p[0].x)*(p[1].y-p[0].y); }
""",
"linkedlist": r"""
struct node { struct node *next; int val; };
int list_sum(const struct node *h){ int s=0; while(h){ s+=h->val; h=h->next; } return s; }
struct node *list_find(struct node *h,int v){ while(h){ if(h->val==v) return h; h=h->next; } return 0; }
""",
"statemachine": r"""
int fsm(const char *in,int n){ int st=0;
  for(int i=0;i<n;i++){ char c=in[i];
    switch(st){ case 0: st = (c=='a')?1:0; break;
                case 1: st = (c=='b')?2:(c=='a'?1:0); break;
                case 2: st = (c=='c')?3:0; break;
                case 3: return 1; } } return st==3; }
""",
"checksum": r"""
unsigned crc32_step(unsigned crc, unsigned char b){ crc ^= b;
  for(int i=0;i<8;i++) crc = (crc>>1) ^ (0xEDB88320u & (-(crc&1))); return crc; }
unsigned fletcher16(const unsigned char *d,int n){ unsigned s1=0,s2=0;
  for(int i=0;i<n;i++){ s1=(s1+d[i])%255; s2=(s2+s1)%255; } return (s2<<8)|s1; }
""",
"fixedpoint": r"""
int fp_mul(int a,int b){ return (int)(((long)a*b)>>16); }
int fp_div(int a,int b){ return (int)(((long)a<<16)/b); }
int isqrt(long n){ long x=n, y=(x+1)/2; while(y<x){ x=y; y=(x+n/x)/2; } return (int)x; }
""",
}

for name, body in PROGRAMS.items():
    (SRC / f"{name}.c").write_text(body.lstrip())
print(f"wrote {len(PROGRAMS)} source files to {SRC}")
