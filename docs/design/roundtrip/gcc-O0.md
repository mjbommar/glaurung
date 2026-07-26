<!-- GENERATED. Regenerate with:
       tools/roundtrip_review.py --out docs/design/roundtrip/gcc-O0.md
     Snapshot taken 2026-07-26 at commit ea9d4b8. It WILL go stale; the tool is the
     source of truth, this file is here so the current state is reviewable without
     running anything. -->

# Round-trip review — gcc -O0

The verdict is the execution differential: our decompiled C is recompiled and
run against the original on the same inputs. It is the only one of our three
measurements that knows whether the code is RIGHT.

**9 of 25 executed functions behave correctly (36%).**

| verdict | count | meaning |
|---|---|---|
| correct | 9 | same answer as the original on every input |
| WRONG | 16 | different answer, crash, or mutated buffer |
| not checked | 4 | no call signature from DWARF — NOT a pass |
| did not terminate | 1 | ran past the per-call budget |

`not checked` is the row to distrust. A by-value struct parameter is enough to
stop the harness building a signature, and those are exactly the functions whose
output is wrong — `structs:dist2` reads two locals nothing assigns and still
scores a graph edit distance of 0.0.
## arith  (gcc -O0)

### `addmul` — **correct**  
`36 cases`

SOURCE:
```c
long addmul(long a, long b, long c) { return a * b + c - (a ^ b); }
```
OURS:
```c
// glaurung: addmul @ 0x10f9
long addmul(long arg0, long arg1, long arg2) {
    // x86-64 epilogue: restore rbp
    return (((arg0 * arg1) + arg2) - (arg0 ^ arg1));
}
```

### `shifts` — **correct**  
`34 cases`

SOURCE:
```c
unsigned shifts(unsigned x, int n) { return (x << n) | (x >> (32 - n)); }
```
OURS:
```c
// glaurung: shifts @ 0x1130
int shifts(int arg0, int arg1) {
    long t0;
    t0 = ((unsigned long)((unsigned int)(arg1)) & 31);
    // x86-64 epilogue: restore rbp
    return ((arg0 << t0) | ((unsigned int)(arg0) >> ((32 - t0) & 31)));
}
```

### `signs` — **WRONG**  
`return 0 != -410965304 on [0, 0]`

SOURCE:
```c
int signs(int a, int b) { return (a < 0 ? -a : a) + (b > a ? b - a : a - b); }
```
OURS:
```c
// glaurung: signs @ 0x114c
int signs(int arg0, int arg1) {
    long sf;
    long var0;
    long var3;
    long var9;
    var0 = (unsigned long)((unsigned int)(arg0));
    if (sf) {
        var3 = var0;
    }
    sf = ((arg1 - arg0) < 0);
    if ((arg0 < arg1)) {
    } else {
    }
    // x86-64 epilogue: restore rbp
    return (var9 + var3);
}
```

## arrays  (gcc -O0)

### `max_array` — **WRONG**  
`return 49 != 1347474224 on [[19, -20, 24, 22, -48, -49, -37, -13, -13, 26, 17, -24, -58, 9, -61, 49], 100]`

SOURCE:
```c
int max_array(const int *a,int n){ int m=a[0]; for(int i=1;i<n;i++) if(a[i]>m)m=a[i]; return m; }
```
OURS:
```c
// glaurung: max_array @ 0x1142
int max_array(int * arg0, int arg1) {
    int local_4;
    int local_8;
    local_8 = *(int *)((long)arg0);
    local_4 = 1;
    while ((local_4 < arg1)) {
        if ((local_8 < arg0[(int)(local_4)])) {
            local_8 = arg0[(int)(local_4)];
        }
        local_4 = (local_4 + 1);
    }
    // x86-64 epilogue: restore rbp
    return local_8;
}
```

### `reverse` — **WRONG**  
`worker crashed (exit -11; )`

SOURCE:
```c
void reverse(int *a,int n){ for(int i=0,j=n-1;i<j;i++,j--){ int t=a[i];a[i]=a[j];a[j]=t; } }
```
OURS:
```c
// glaurung: reverse @ 0x11a8
int reverse(int * arg0, int arg1) {
    int local_4;
    int local_8;
    int local_c;
    long ret;
    local_c = 0;
    local_8 = (arg1 - 1);
    ret = (unsigned long)((unsigned int)(local_c));
    while ((local_c < local_8)) {
        local_4 = arg0[(int)(local_c)];
        *(int *)(((long)arg0 + (0 + ((int)(local_c) * 4)))) = arg0[(int)(local_8)];
        *(int *)(((0 + ((int)(local_8) * 4)) + (long)arg0)) = local_4;
        local_c = (local_c + 1);
        local_8 = (local_8 - 1);
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```

### `sum_array` — **WRONG**  
`return -24 != 1515403205 on [[-46, -14, 38, -25, 1, -29, -64, -6, -37, 25, 60, 60, 6, -23, -12, 42], 100]`

SOURCE:
```c
int sum_array(const int *a, int n){ int s=0; for(int i=0;i<n;i++) s+=a[i]; return s; }
```
OURS:
```c
// glaurung: sum_array @ 0x10f9
int sum_array(int * arg0, int arg1) {
    int local_4;
    int local_8;
    local_8 = 0;
    local_4 = 0;
    while ((local_4 < arg1)) {
        local_8 = (local_8 + arg0[(int)(local_4)]);
        local_4 = (local_4 + 1);
    }
    // x86-64 epilogue: restore rbp
    return local_8;
}
```

## branches  (gcc -O0)

### `classify` — **correct**  
`34 cases`

SOURCE:
```c
int classify(int a,int b){ if(a>b) return a-b; else if(a<b) return b-a; return 0; }
```
OURS:
```c
// glaurung: classify @ 0x10f9
int classify(int arg0, int arg1) {
    long ret;
    if ((arg0 <= arg1)) {
        if ((arg0 < arg1)) {
            ret = ((unsigned long)((unsigned int)(arg1)) - (unsigned long)((unsigned int)(arg0)));
        } else {
            ret = 0;
        }
    } else {
        ret = ((unsigned long)((unsigned int)(arg0)) - (unsigned long)((unsigned int)(arg1)));
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```

### `nested` — **correct**  
`34 cases`

SOURCE:
```c
int nested(int x,int y,int z){ if(x){ if(y) return z; else return -z; } return 0; }
```
OURS:
```c
// glaurung: nested @ 0x112e
int nested(int arg0, int arg1, int arg2) {
    long ret;
    if ((arg0 == 0)) {
        ret = 0;
    } else {
        if ((arg1 != 0)) {
            ret = (unsigned long)((unsigned int)(arg2));
        } else {
            ret = (-(unsigned long)((unsigned int)(arg2)));
        }
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```

## checksum  (gcc -O0)

### `crc32_step` — **correct**  
`31 cases`

SOURCE:
```c
unsigned crc32_step(unsigned crc, unsigned char b){ crc ^= b;
  for(int i=0;i<8;i++) crc = (crc>>1) ^ (0xEDB88320u & (-(crc&1))); return crc; }
```
OURS:
```c
// glaurung: crc32_step @ 0x10f9
int crc32_step(int arg0, int arg1) {
    int local_14;
    signed char local_18;
    int local_4;
    local_14 = arg0;
    local_18 = arg1;
    local_14 = (local_14 ^ (unsigned char)(local_18));
    local_4 = 0;
    while ((local_4 <= 7)) {
        local_14 = (((-(local_14 & 1)) & -0x12477ce0) ^ ((unsigned int)(local_14) >> 1));
        local_4 = (local_4 + 1);
    }
    // x86-64 epilogue: restore rbp
    return local_14;
}
```

### `fletcher16` — **WRONG**  
`return 15934 != 4261625149 on [[62, 187, 162, 183, 212, 65, 130, 216, 31, 161, 232, 40, 169, 178, 154, 163], 1]`

SOURCE:
```c
unsigned fletcher16(const unsigned char *d,int n){ unsigned s1=0,s2=0;
  for(int i=0;i<n;i++){ s1=(s1+d[i])%255; s2=(s2+s1)%255; } return (s2<<8)|s1; }
```
OURS:
```c
// glaurung: fletcher16 @ 0x1141
int fletcher16(char * arg0, int arg1) {
    int local_4;
    int local_8;
    int local_c;
    long ret;
    long var17;
    long var5;
    long var6;
    local_c = 0;
    local_8 = 0;
    local_4 = 0;
    while ((local_4 < arg1)) {
        ret = (unsigned char)(arg0[(int)(local_4)]);
        var5 = (unsigned char)(ret);
        var6 = (var5 + (unsigned long)((unsigned int)(local_c)));
        ret = ((unsigned long)((-0x7f7f7f7f * var6)) >> 32);
        local_c = ((unsigned long)(ret) >> 7);
        local_c = (var6 - ((local_c << 8) - local_c));
        var17 = ((unsigned long)((unsigned int)(local_8)) + (unsigned long)((unsigned int)(local_c)));
        ret = ((unsigned long)((-0x7f7f7f7f * var17)) >> 32);
        local_8 = ((unsigned long)(ret) >> 7);
        local_8 = (var17 - ((local_8 << 8) - local_8));
        local_4 = (local_4 + 1);
    }
    ret = (((unsigned long)((unsigned int)(local_8)) << 8) | (unsigned long)((unsigned int)(local_c)));
    // x86-64 epilogue: restore rbp
    return ret;
}
```

## fixedpoint  (gcc -O0)

### `fp_div` — **WRONG**  
`worker crashed (exit -8; )`

SOURCE:
```c
int fp_div(int a,int b){ return (int)(((long)a<<16)/b); }
```
OURS:
```c
// glaurung: fp_div @ 0x111c
long fp_div(int arg0, int arg1) {
    long var2;
    var2 = ((int)(arg0) << 16);
    // x86-64 epilogue: restore rbp
    return (var2 / (int)(arg1));
}
```

### `fp_mul` — **WRONG**  
`return -65536 != 0 on [2147483647, 2147483647]`

SOURCE:
```c
int fp_mul(int a,int b){ return (int)(((long)a*b)>>16); }
```
OURS:
```c
// glaurung: fp_mul @ 0x10f9
long fp_mul(int arg0, int arg1) {
    // x86-64 epilogue: restore rbp
    return (((int)(arg1) * (int)(arg0)) >> 16);
}
```

### `isqrt` — **WRONG**  
`return 0 != -1257966797 on [9223372036854775807]`

SOURCE:
```c
int isqrt(long n){ long x=n, y=(x+1)/2; while(y<x){ x=y; y=(x+n/x)/2; } return (int)x; }
```
OURS:
```c
// glaurung: isqrt @ 0x1140
long isqrt(long arg0) {
    long local_10;
    long local_8;
    long var14;
    long var2;
    local_10 = arg0;
    var2 = (local_10 + 1);
    local_8 = ((var2 + ((unsigned long)(var2) >> 63)) >> 1);
    while ((local_8 < local_10)) {
        local_10 = local_8;
        var14 = (local_10 + (arg0 / local_10));
        local_8 = ((var14 + ((unsigned long)(var14) >> 63)) >> 1);
    }
    // x86-64 epilogue: restore rbp
    return local_10;
}
```

## linkedlist  (gcc -O0)

### `list_find` — **not checked**  
`signature not recoverable from DWARF`

SOURCE:
```c
struct node *list_find(struct node *h,int v){ while(h){ if(h->val==v) return h; h=h->next; } return 0; }
```
OURS:
```c
// glaurung: list_find @ 0x112f
int list_find(long arg0, int arg1) {
    long local_8;
    long ret;
    // x86-64 prologue: save rbp
    local_8 = arg0;
    while ((local_8 != 0)) {
        if ((arg1 != *(int *)((local_8 + 0x8)))) {
            local_8 = *(long *)(local_8);
        } else {
            ret = local_8;
        }
        return ret;
    }
    ret = 0;
}
```

### `list_sum` — **not checked**  
`signature not recoverable from DWARF`

SOURCE:
```c
int list_sum(const struct node *h){ int s=0; while(h){ s+=h->val; h=h->next; } return s; }
```
OURS:
```c
// glaurung: list_sum @ 0x10f9
int list_sum(long arg0) {
    long local_18;
    int local_4;
    local_18 = arg0;
    local_4 = 0;
    while ((local_18 != 0)) {
        local_4 = (local_4 + *(int *)((local_18 + 0x8)));
        local_18 = *(long *)(local_18);
    }
    // x86-64 epilogue: restore rbp
    return local_4;
}
```

## loops  (gcc -O0)

### `count_bits` — **correct**  
`31 cases`

SOURCE:
```c
int count_bits(unsigned x){ int c=0; do { c += x&1; x>>=1; } while(x); return c; }
```
OURS:
```c
// glaurung: count_bits @ 0x1166
int count_bits(int arg0) {
    int local_4;
    local_4 = 0;
    while (1) {
        local_4 = (local_4 + (arg0 & 1));
        arg0 = ((unsigned int)(arg0) >> 1);
        if ((arg0 == 0)) {
            break;
        }
    }
    // x86-64 epilogue: restore rbp
    return local_4;
}
```

### `factorial` — **correct**  
`34 cases`

SOURCE:
```c
long factorial(int n){ long f=1; while(n>1){ f*=n; n--; } return f; }
```
OURS:
```c
// glaurung: factorial @ 0x1130
long factorial(int arg0) {
    long local_8;
    local_8 = 1;
    while ((1 < arg0)) {
        local_8 = ((int)(arg0) * local_8);
        arg0 = (arg0 - 1);
    }
    // x86-64 epilogue: restore rbp
    return local_8;
}
```

### `sum_to` — **correct**  
`34 cases`

SOURCE:
```c
long sum_to(int n){ long s=0; for(int i=0;i<n;i++) s+=i; return s; }
```
OURS:
```c
// glaurung: sum_to @ 0x10f9
long sum_to(int arg0) {
    long local_8;
    int local_c;
    local_8 = 0;
    local_c = 0;
    while ((local_c < arg0)) {
        local_8 = (local_8 + (int)(local_c));
        local_c = (local_c + 1);
    }
    // x86-64 epilogue: restore rbp
    return local_8;
}
```

## matrix  (gcc -O0)

### `matmul` — **WRONG**  
`worker crashed (exit -11; )`

SOURCE:
```c
void matmul(const int *A,const int *B,int *C,int n){
  for(int i=0;i<n;i++) for(int j=0;j<n;j++){ int s=0;
    for(int k=0;k<n;k++) s+=A[i*n+k]*B[k*n+j]; C[i*n+j]=s; } }
```
OURS:
```c
// glaurung: matmul @ 0x10f9
int matmul(int * arg0, int * arg1, int * arg2, int arg3) {
    int local_10;
    int local_4;
    int local_8;
    int local_c;
    long ret;
    local_10 = 0;
    ret = (unsigned long)((unsigned int)(local_10));
    while ((local_10 < arg3)) {
        local_c = 0;
        while ((local_c < arg3)) {
            local_8 = 0;
            local_4 = 0;
            while ((local_4 < arg3)) {
                local_8 = (local_8 + (arg1[(int)((local_c + (local_4 * arg3)))] * arg0[(int)((local_4 + (local_10 * arg3)))]));
                local_4 = (local_4 + 1);
            }
            *(int *)(((0 + ((int)((local_c + (local_10 * arg3))) * 4)) + (long)arg2)) = local_8;
            local_c = (local_c + 1);
        }
        local_10 = (local_10 + 1);
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```

## recursion  (gcc -O0)

### `fib` — **did not terminate**  
`worker exceeded 60s`

SOURCE:
```c
long fib(int n){ if(n<2) return n; return fib(n-1)+fib(n-2); }
long ackermann(long m,long n){ if(m==0)return n+1; if(n==0)return ackermann(m-1,1);
  return ackermann(m-1, ackermann(m,n-1)); }
```
OURS:
```c
// glaurung: fib @ 0x10f9
int fib(int arg0) {
    long ret;
    long var4;
    long var5;
    long var8;
    // x86-64 prologue: save rbp
    if ((arg0 <= 1)) {
        ret = (int)(arg0);
    } else {
        var4 = fib((arg0 - 1));
        var5 = var4;
        var8 = fib((arg0 - 2));
        ret = (var8 + var5);
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```

## sort  (gcc -O0)

### `bsearch_i` — **WRONG**  
`return -1 != 0 on [[-8, -5, -2, 1, 4, 7, -7, -4, -1, 2, 5, 8, -6, -3, 0, 3], 0, 0]`

SOURCE:
```c
int bsearch_i(const int *a,int n,int key){ int lo=0,hi=n-1;
  while(lo<=hi){ int m=(lo+hi)/2; if(a[m]==key)return m; if(a[m]<key)lo=m+1; else hi=m-1; } return -1; }
```
OURS:
```c
// glaurung: bsearch_i @ 0x11e5
int bsearch_i(int * arg0, int arg1, int arg2) {
    int local_4;
    int local_8;
    int local_c;
    long ret;
    long var5;
    // x86-64 prologue: save rbp
    local_c = 0;
    local_8 = (arg1 - 1);
    while ((local_c <= local_8)) {
        var5 = ((unsigned long)((unsigned int)(local_8)) + (unsigned long)((unsigned int)(local_c)));
        local_4 = ((var5 + ((unsigned long)(var5) >> 31)) >> 1);
        if ((arg2 != arg0[(int)(local_4)])) {
            if ((arg0[(int)(local_4)] < arg2)) {
                local_c = (local_4 + 1);
            } else {
                local_8 = (local_4 - 1);
            }
        } else {
            ret = (unsigned long)((unsigned int)(local_4));
        }
        return ret;
    }
    ret = -1;
}
```

### `bubble` — **WRONG**  
`buffer mutation differs on [[-46, -64, 44, -42, 36, -13, -62, 32, -46, -16, 55, -5, 52, 56, 40, 51], 100]`

SOURCE:
```c
void bubble(int *a,int n){ for(int i=0;i<n;i++) for(int j=0;j<n-1-i;j++)
    if(a[j]>a[j+1]){ int t=a[j];a[j]=a[j+1];a[j+1]=t; } }
```
OURS:
```c
// glaurung: bubble @ 0x10f9
int bubble(int * arg0, int arg1) {
    int local_4;
    int local_8;
    int local_c;
    long ret;
    local_c = 0;
    ret = (unsigned long)((unsigned int)(local_c));
    while ((local_c < arg1)) {
        local_8 = 0;
        while ((local_8 < ((arg1 - 1) - local_c))) {
            if ((arg0[((int)(local_8) + 1)] < arg0[(int)(local_8)])) {
                local_4 = arg0[(int)(local_8)];
                *(int *)(((long)arg0 + (0 + ((int)(local_8) * 4)))) = arg0[((int)(local_8) + 1)];
                *(int *)(((0 + (((int)(local_8) + 1) * 4)) + (long)arg0)) = local_4;
            }
            local_8 = (local_8 + 1);
        }
        local_c = (local_c + 1);
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```

## statemachine  (gcc -O0)

### `fsm` — **WRONG**  
`return 0 != 253 on [[253, 85, 126, 121, 116, 186, 145, 174, 72, 245, 50, 111, 228, 83, 170, 6], 1]`

SOURCE:
```c
int fsm(const char *in,int n){ int st=0;
  for(int i=0;i<n;i++){ char c=in[i];
    switch(st){ case 0: st = (c=='a')?1:0; break;
                case 1: st = (c=='b')?2:(c=='a'?1:0); break;
                case 2: st = (c=='c')?3:0; break;
                case 3: return 1; } } return st==3; }
```
OURS:
```c
// glaurung: fsm @ 0x10f9
signed char fsm(char * arg0, int arg1) {
    int local_4;
    int local_8;
    signed char local_9;
    long ret;
    long var5;
    long zf;
    // x86-64 prologue: save rbp
    local_8 = 0;
    local_4 = 0;
    zf = (local_4 == arg1);
    while ((local_4 < arg1)) {
        ret = (unsigned char)(arg0[(int)(local_4)]);
        local_9 = var5;
        if ((local_8 == 3)) {
            ret = 1;
        } else {
            if ((3 < local_8)) {
                goto L_11a0;
            }
        }
        return ret;
    }
    zf = (local_8 == 3);
    ret = (unsigned char)(zf);
    if ((local_8 == 2)) {
        goto L_1181;
    }
    zf = (local_8 == 2);
    if ((2 < local_8)) {
        goto L_11a0;
    }
    if ((local_8 == 0)) {
        goto L_1154;
    }
    if ((local_8 == 1)) {
        goto L_1163;
    }
    goto L_11a0;
    L_1154: ;
    zf = (local_9 == 97);
    local_8 = (unsigned char)(zf);
    goto L_11a0;
    L_1163: ;
    if ((local_9 == 98)) {
        goto L_1178;
    }
    zf = (local_9 == 97);
    local_8 = (unsigned char)(zf);
    goto L_11a0;
    L_1178: ;
    local_8 = 2;
    goto L_11a0;
    L_1181: ;
    if ((local_9 != 99)) {
        goto L_1190;
    }
    local_8 = 3;
    goto L_11a0;
    L_1190: ;
    local_8 = 0;
    goto L_11a0;
    L_11a0: ;
    local_4 = (local_4 + 1);
}
```

## strops  (gcc -O0)

### `hash_djb2` — **WRONG**  
`decompiled function did not terminate within 5.0s on an input the original returned on`

SOURCE:
```c
unsigned hash_djb2(const char *s){ unsigned h=5381; int c; while((c=*s++)) h=((h<<5)+h)+c; return h; }
```
OURS:
```c
// glaurung: hash_djb2 @ 0x117e
int hash_djb2(long arg0) {
    long local_18;
    int local_4;
    int local_8;
    long ret;
    long var0;
    local_18 = arg0;
    local_8 = 0x1505;
    var0 = local_18;
    local_18 = (local_18 + 1);
    ret = (unsigned char)(*(char *)((var0)));
    local_4 = (signed char)(ret);
    while ((local_4 != 0)) {
        local_8 = (local_4 + ((local_8 << 5) + local_8));
    }
    ret = (unsigned long)((unsigned int)(local_8));
    // x86-64 epilogue: restore rbp
    return local_8;
}
```

### `str_cmp` — **WRONG**  
`return 2 != 0 on [[14, 17, 20, 23, 26, 29, 32, 35, 38, 41, 44, 47, 50, 53, 56, 59], [14, 17, 20, 23, 26, 29, 32, 35, 38, 41, 44, 47, 50, 53, 56, 59]]`

SOURCE:
```c
int str_cmp(const char *a,const char *b){ while(*a&&*a==*b){a++;b++;} return *a-*b; }
```
OURS:
```c
// glaurung: str_cmp @ 0x112b
int str_cmp(char * arg0, char * arg1) {
    long ret;
    long var4;
    long var6;
    long var8;
    long var9;
    ret = (unsigned char)(*(char *)((long)arg0));
    while ((ret != 0)) {
        ret = (unsigned char)(*(char *)((long)arg1));
        if ((var4 != ret)) {
            ret = (unsigned char)(*(char *)((long)arg0));
            var6 = (signed char)(ret);
            ret = (unsigned char)(*(char *)((long)arg1));
            var8 = (signed char)(ret);
            var9 = (var6 - var8);
            ret = var9;
            return var9;
        }
        arg0 = (char *)(((long)arg0 + 1));
        arg1 = (char *)(((long)arg1 + 1));
    }
    ret = (unsigned char)(*(char *)((long)arg0));
    var6 = (signed char)(ret);
    ret = (unsigned char)(*(char *)((long)arg1));
    var8 = (signed char)(ret);
    var9 = (var6 - var8);
    ret = var9;
    // x86-64 epilogue: restore rbp
    return var9;
}
```

### `str_len` — **WRONG**  
`decompiled function did not terminate within 5.0s on an input the original returned on`

SOURCE:
```c
int str_len(const char *s){ int n=0; while(s[n]) n++; return n; }
```
OURS:
```c
// glaurung: str_len @ 0x10f9
int str_len(char * arg0) {
    int local_4;
    long ret;
    local_4 = 0;
    ret = (unsigned char)(arg0[(int)(local_4)]);
    while ((ret != 0)) {
        local_4 = (local_4 + 1);
    }
    ret = (unsigned long)((unsigned int)(local_4));
    // x86-64 epilogue: restore rbp
    return local_4;
}
```

## structs  (gcc -O0)

### `dist2` — **not checked**  
`signature not recoverable from DWARF`

SOURCE:
```c
long dist2(struct pt a, struct pt b){ long dx=a.x-b.x, dy=a.y-b.y; return dx*dx+dy*dy; }
```
OURS:
```c
// glaurung: dist2 @ 0x10f9
int dist2(long arg0, long arg1) {
    long local_10;
    int local_14;
    int local_1c;
    long local_8;
    local_10 = (int)((arg0 - arg1));
    local_8 = (int)((local_14 - local_1c));
    // x86-64 epilogue: restore rbp
    return ((local_8 * local_8) + (local_10 * local_10));
}
```

### `rect_area` — **not checked**  
`signature not recoverable from DWARF`

SOURCE:
```c
int rect_area(const struct pt *p){ return (p[1].x-p[0].x)*(p[1].y-p[0].y); }
```
OURS:
```c
// glaurung: rect_area @ 0x113f
int rect_area(int * arg0) {
    long var8;
    var8 = ((long)arg0 + 8);
    // x86-64 epilogue: restore rbp
    return ((*(int *)(((long)arg0 + 8)) - *(int *)((long)arg0)) * (*(int *)((var8 + 0x4)) - *(int *)(((long)arg0 + 0x4))));
}
```

## switch_jt  (gcc -O0)

### `dispatch` — **correct**  
`34 cases`

SOURCE:
```c
int dispatch(int op, int a, int b){
  switch(op){ case 0:return a+b; case 1:return a-b; case 2:return a*b;
              case 3:return a&b; case 4:return a|b; case 5:return a^b;
              case 6:return a<<1; case 7:return b>>1; default:return -1; } }
```
OURS:
```c
// glaurung: dispatch @ 0x10f9
int dispatch(int arg0, int arg1, int arg2) {
    long ret;
    switch (arg0) {
        case 7:
            ret = (arg2 >> 1);
            break;
        case 6:
            ret = ((unsigned long)((unsigned int)(arg1)) + (unsigned long)((unsigned int)(arg1)));
            break;
        case 5:
            ret = ((unsigned long)((unsigned int)(arg1)) ^ (unsigned long)((unsigned int)(arg2)));
            break;
        case 4:
            ret = ((unsigned long)((unsigned int)(arg1)) | (unsigned long)((unsigned int)(arg2)));
            break;
        case 3:
            ret = ((unsigned long)((unsigned int)(arg1)) & (unsigned long)((unsigned int)(arg2)));
            break;
        case 2:
            ret = ((unsigned long)((unsigned int)(arg1)) * (unsigned long)((unsigned int)(arg2)));
            break;
        case 0:
            ret = ((unsigned long)((unsigned int)(arg2)) + (unsigned long)((unsigned int)(arg1)));
            break;
        case 1:
            ret = ((unsigned long)((unsigned int)(arg1)) - (unsigned long)((unsigned int)(arg2)));
            break;
        default:
            ret = -1;
            break;
    }
    // x86-64 epilogue: restore rbp
    return ret;
}
```
