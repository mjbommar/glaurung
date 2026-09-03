# Primary measurements (2026-09-03, this box: Ubuntu 26.04, gcc 15.2.0, glibc 2.43)

> **Kind:** design · **Status:** proposed


## Archives on the host
| file | bytes | ar members | T/t/W/i syms |
|---|---|---|---|
| /usr/lib/x86_64-linux-gnu/libc.a | 6,238,228 | 2,233 | 5,008 (4,559 with size>=16) |
| /usr/lib/x86_64-linux-gnu/libm-2.43.a | 3,112,678 | - | - |
| /usr/lib/gcc/x86_64-linux-gnu/15/libstdc++.a | 6,730,712 | 191 | 6,375 |
| /usr/lib/x86_64-linux-gnu/libcrypto.a | 11,950,148 | 1,015 | 13,256 |
| /usr/lib/x86_64-linux-gnu/libssl.a | 2,096,114 | 95 | 2,443 |
| /usr/lib/x86_64-linux-gnu/libz.a | 150,838 | 15 | 129 |
libm.a and libpthread.a are GNU ld scripts / empty (glibc >=2.34 merge; libm.a real file is libm-2.43.a).
2,187 .a files installed on this box. libnewlib-arm-none-eabi ships 39 distinct libc.a multilib variants.

## Signature build (existing builder, unchanged)
| library | raw | unique sigs | dropped ambiguous | JSON bytes | B/sig |
|---|---|---|---|---|---|
| glibc 2.43 | 4375 | 2690 | 137 | 2,743,719 | 1020 |
| libstdc++ 15.2.0 | 4870 | 2179 | 354 | 2,807,090 | 1288 |
| libcrypto 3.5 | 9919 | 7066 | 574 | 7,928,365 | 1122 |
| libssl 3.5 | 2070 | 1899 | 67 | 2,104,436 | 1108 |
| libz 1.3.1 | 120 | 112 | 4 | 68,563 | 612 |
| libm 2.43 | 1859 | 682 | 43 | 2,001,054 | 2934 |
| rust std 1.90 rlib | 1183 | 906 | 0 | 1,021,584 | 1127 |
TOTAL 15,534 sigs, 18.7 MB JSON (1202 B/sig). Build time ~0.15 s wall for glibc.

## Encoding sizes (measured, same 15,534 sigs)
- JSON:                      18,674,811 B  (1202 B/sig)
- packed binary, interned:    1,776,682 B  ( 114 B/sig)  = 10.5x smaller
- packed + zstd-19:             804,839 B  (  52 B/sig)  = 23x smaller
- JSON + zstd-19 (glibc only): 186,372 vs 2,743,719 raw (14.7x); libcrypto 450,985 vs 7,928,365 (17.6x)
- distinct fn names 15,418; distinct ref names 10,279; union strtab 581,838 B
- python json.load of all 18.7 MB: 0.072 s

## End-to-end match, real static binary
gcc -O2 -static, stripped, 817,040 B, 1,090 defined code-symbol addresses.
Matched with the glibc 2.43 library built from this box's own libc.a:
  747 hits: 731 unique + 16 ambiguous.  731 correct, 0 wrong. Precision 1.000. 0.27 s.
  evidence: flirt-L2 649, flirt-L1 82.

## Cross-version / cross-distro decay (same target binary)
| library used | correct | wrong |
|---|---|---|
| glibc 2.43 (this box, exact) | 731 | 0 |
| glibc 2.41-12 (Debian trixie) | 1 | 0 |
| glibc 2.36-9 (Debian bookworm) | 0 | 0 |
| glibc 2.31 (Debian bullseye) | 0 | 0 |

Signature-level identity (masked pattern + mask + crc16 + crc_len) over shared names:
| pair | shared names | identical sigs | % |
|---|---|---|---|
| ubuntu26.04/2.43 vs deb/2.41 | 2511 | 5 | 0.2% |
| ubuntu26.04/2.43 vs deb/2.36 | 2318 | 1 | 0.0% |
| ubuntu26.04/2.43 vs deb/2.31 | 1842 | 0 | 0.0% |
| deb 2.41 vs deb 2.36 (same distro line) | 2429 | 1045 | 43.0% |
| deb 2.36 vs deb 2.31 (same distro line) | 1973 | 514 | 26.1% |

## Latent defect found at scale
Builder ambiguity key includes `function_len`; the matcher never compares it.
Over the 7-library merged set: 268 keys (576 signatures, 3.7%) are indistinguishable
to the matcher but survive as distinct entries. Example: glibc `_IO_seekoff` (len 646)
and `_IO_seekpos` (len 492) share prologue, an all-fixed mask, and crc16=7706/crc_len=1.
Referenced names break 251 of the 268; 17 have identical ref sets too.
16 of the 268 are cross-library (e.g. glibc `__res_randomid` vs libstdc++
`_ZNSt6chrono3_V212steady_clock3nowEv`).

## crc_len / mask distributions over the 15,534
crc_len == 0: 2,732; 1-3: 1,251; 4-15: 3,701; >=16: 7,850. median 16, mean 40.5.
fixed bytes in the 32-byte window: median 32, min 16, 60.3% fully fixed.

## snapshot.debian.org (verified working, no auth)
GET https://snapshot.debian.org/mr/binary/libc6-dev/            -> 813 versions, 2.0.7t-1 (1998) .. 2.44-1
GET https://snapshot.debian.org/mr/binary/libc6-dev/2.36-9/binfiles?fileinfo=1 -> per-arch SHA-1 hash
GET https://snapshot.debian.org/file/<sha1>                     -> the .deb itself
dpkg-deb -x <deb> <dir>                                          -> usr/lib/<triple>/libc.a  (no root)
libc6-dev_2.36-9_amd64.deb 1,898,160 B -> libc.a 5,445,986 B
libc6-dev_2.41-12_amd64.deb 1,990,664 B -> libc.a 5,670,198 B
libc6-dev_2.31-13+deb11u13_amd64.deb 2,361,872 B -> libc.a 5,357,318 B

## Rust
.rlib is an ar archive ("!<arch>"): members lib.rmeta, lib.rmeta-link, <crate>.rcgu.o
libstd-*.rlib 11,667,026 B, 3 members, 1,333 T/t syms; libcore-*.rlib 2,929,948 B, 566 T/t.
Sysroot lib dir per stable toolchain: 27 rlibs, 162 MB.
