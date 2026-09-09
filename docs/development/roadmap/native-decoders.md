# Glaurung-native instruction decoders

> **Kind:** plan · **Status:** active

This workstream replaces Capstone's production capabilities inside Glaurung
with safe, portable Rust decoders, ports the applicable upstream test estate,
and measures alternative representations rather than preserving Capstone's C
data structures by default. Capstone remains a differential oracle during the
migration, then becomes developer-only and is removed from shipped builds.

Capstone-derived source, tables, and vectors retain the upstream BSD-3-Clause
and LLVM/NCSA notices. The checked-in corpus documents bind every vector to an
upstream version, source path, and line; `tests/corpora/capstone/NOTICE.md`
reproduces the required notices.

## Completion contract

- [~] AArch64: native decoder is a production-first backend for implemented
  families; immediate, conditional, compare, test-bit, and register branch
  families, PC-relative address generation, and add/subtract immediate are
  native; scalar unsigned-offset loads/stores are native with structured widths
  and access, as are move-wide, logical-immediate, and add/subtract
  extended/shifted-register forms, add/subtract-with-carry, and logical
  shifted-register forms. Conditional selects and their canonical aliases are
  native, as are scalar multiply, bitfield/extension aliases, extract, integer
  division, register shifts/rotates, and one-source bit/reversal/count forms.
  Integer unscaled, pre-index, and post-index loads/stores are also native.
  Scalar register-offset loads/stores retain structured base, index, scale, and
  lossless extension text. Scalar SIMD/FP `b`/`h`/`s`/`d`/`q` loads and stores
  are native across unsigned-offset, unscaled, pre-index, post-index, and
  register-offset forms with the same structured addressing guarantees.
  Exception-generation instructions, architectural hints, barriers, and
  exception returns are native as compact mask/field decoders rather than
  opcode tables. `MRS`, register and immediate `MSR`, named system registers,
  and generic encoded system-register spellings are native; their packed name
  index, including the GICv3 and trace-register MC suites, lives in the
  dependency-free WASM-capable crate. Raw `SYS`/`SYSL` and
  the `AT`, `DC`, `IC`, and `TLBI` aliases share that packed string pool and
  retain architectural fields the current Capstone adapter drops.
  Scalar floating-point compare, conditional compare/select, move, convert,
  round, unary arithmetic, binary arithmetic, and fused multiply-add/subtract
  families are native for the half, single, and double encodings admitted by
  each operation. Fixed-point and integer conversion families are native across
  signed/unsigned 32- and 64-bit integer inputs, represented FP widths, and all
  legal fractional-bit scales. Scalar literal and unprivileged loads/stores,
  exclusive and ordered loads/stores, prefetch forms, CRC32 operations, FP
  immediate and integer-register/lane moves, SP `mov`, and `bfc` are native.
  Advanced SIMD scalar `abs`/`neg`, saturating `sqabs`/`sqneg`, and floating
  absolute difference are native, as are scalar 64-bit `add`/`sub` and
  signed/unsigned variable shifts. Integer and floating pairwise-add reductions
  preserve their packed source-vector shape structurally. Saturating signed,
  unsigned, and mixed-sign addition/subtraction plus saturating and rounding
  variable shifts share the same field-driven scalar decoder. Scalar integer
  equality, signed/unsigned relational, test-bits, and compare-with-zero forms
  are native and reject the reserved element sizes and unsigned `cmlt` form.
  Scalar single/double floating-point equality, ordered and absolute relational
  comparisons, including their compare-with-zero forms, are native as compact
  mask/field decoders. Saturating signed/unsigned narrowing and signed-to-
  unsigned narrowing derive source/destination widths from one size field.
  Scalar reciprocal-step, reciprocal-square-root-step, reciprocal-estimate,
  reciprocal-exponent, and reciprocal-square-root-estimate forms are native.
  Scalar saturating doubling multiply-high, rounding multiply-high, widening
  multiply, widening multiply-accumulate/subtract, and floating multiply-
  extended forms share one field decoder with explicit destination access.
  Indexed-lane scalar `fmul`/`fmulx` preserve vector identity, element width,
  and lane index structurally; indexed `fmla`/`fmls` reuse the same field
  decoder and preserve their accumulating destination as `ReadWrite`.
  Register extensions and shifts survive in lossless operand text even
  though the legacy adapter drops them. Logical immediates are expanded
  algorithmically from the compact replicated-bitmask encoding; no decode table
  is shipped. Integer, sign-extending, and SIMD pair loads/stores are native
  across offset, pre-index, post-index, and non-temporal modes. Capstone remains
  the fallback for the remaining families.
- [ ] ARM A32 and Thumb, including M-profile fallback behavior.
- [ ] MIPS32/MIPS64.
- [ ] PowerPC32/PowerPC64.
- [ ] RISC-V32/RISC-V64.
- [ ] No production module imports Capstone or links `capstone-sys`.
- [ ] Applicable Capstone MC/regression vectors are vendored with provenance,
  converted to structured assertions, and run in CI.
- [ ] Differential native-versus-Capstone testing covers every migrated family
  until Capstone removal; specification/construction truth resolves disputes.
- [ ] Decoder fuzzing covers valid, invalid, truncated, endian, and mode inputs.
- [~] The extracted dependency-free `glaurung-disasm` core compiles for
  `wasm32-unknown-unknown` and runs its native portable-primitive suite. The
  decoder families and corpus assertions still need to move across this seam,
  followed by a WASM test runner; this is not yet a full-Glaurung WASM claim.
- [ ] Size and throughput baselines compare direct matches, compact tables,
  generated decision trees, and any release-only embedding/compression choice.
- [ ] The winning representation is selected from measurements, with decode
  correctness and bounded memory taking precedence over throughput.
- [ ] Existing Rust, Python, fixture-matrix, cross-architecture, and decompiler
  gates pass without a decoder-attributable regression.

## Ordered implementation

1. Tighten the existing `Disassembler` seam and make AArch64 a hybrid whose
   native implementation is tried before the Capstone oracle.
2. Port AArch64 family-by-family, beginning with control flow because CFG
   discovery is a production consumer and branch targets have exact oracles.
3. Build a corpus converter for Capstone `.s.cs` MC vectors. Store normalized
   input and expected structured output, not Capstone's presentation buffers.
4. Add coverage accounting by encoding family and refuse promotion when an
   operand or architectural constraint is silently unrepresented.
5. Benchmark generated direct dispatch against compact table interpreters on
   real Glaurung instruction distributions and adversarial byte streams.
6. Repeat for ARM/Thumb, RISC-V, MIPS, and PowerPC; remove each architecture's
   Capstone fallback only after its complete promotion gate passes.
7. Make Capstone test-only, prove the portable WASM lane, then remove the C
   dependency and retained oracle from release artifacts.

## Current evidence

The first production slice routes all AArch64 decoding through the hybrid in
`disasm::registry`. Native control-flow families use compact mask dispatch and
fall back only on the explicit `UnsupportedInstruction` result. All 1,891
active four-byte vectors in Capstone 5.0's `basic-a64-instructions.s.cs`, all
110 vectors in `gicv3-regs.s.cs`, all 382 vectors in `trace-regs.s.cs`, plus
all 273 vectors in all twenty-one scalar NEON MC files, all 184 vectors in fourteen
complete vector NEON MC files, plus four test-bit boundary encodings assembled
from LLVM's AArch64 definitions, carry expected results. This is complete
coverage of those 38 MC files and of the upstream
scalar-NEON file tranche, not complete AArch64
ISA or extension coverage. The importer fails closed if any active four-byte
source line is omitted and rejects conflicting names for the same
system-register encoding and direction. A separate differential test compares
all 2,844 vectors against the current Capstone adapter at a nonzero address.

The checked corpus is reproducible from the bundled upstream source:

```sh
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/basic-a64-instructions.s.cs" \
  tests/corpora/capstone/aarch64-native-slice.json \
  --sysreg-output crates/glaurung-disasm/src/aarch64_sysregs.rs \
  --additional-sysreg-source \
    "$CAPSTONE_SOURCE/suite/MC/AArch64/gicv3-regs.s.cs" \
  --additional-sysreg-source \
    "$CAPSTONE_SOURCE/suite/MC/AArch64/trace-regs.s.cs" --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-scalar-abs.s.cs" \
  tests/corpora/capstone/aarch64-neon-scalar-abs.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-scalar-neg.s.cs" \
  tests/corpora/capstone/aarch64-neon-scalar-neg.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-scalar-add-sub.s.cs" \
  tests/corpora/capstone/aarch64-neon-scalar-add-sub.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-scalar-shift.s.cs" \
  tests/corpora/capstone/aarch64-neon-scalar-shift.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-scalar-reduce-pairwise.s.cs" \
  tests/corpora/capstone/aarch64-neon-scalar-reduce-pairwise.json --check
for stem in saturating-add-sub saturating-rounding-shift saturating-shift \
  rounding-shift compare fp-compare extract-narrow recip mul by-elem-mul \
  by-elem-mla by-elem-saturating-mla by-elem-saturating-mul dup cvt shift-imm; do
  uv run python tools/import_capstone_mc.py \
    "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-scalar-$stem.s.cs" \
    "tests/corpora/capstone/aarch64-neon-scalar-$stem.json" --check
done
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-extract.s.cs" \
  tests/corpora/capstone/aarch64-neon-extract.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-frsqrt-frecp.s.cs" \
  tests/corpora/capstone/aarch64-neon-frsqrt-frecp.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-add-pairwise.s.cs" \
  tests/corpora/capstone/aarch64-neon-add-pairwise.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-facge-facgt.s.cs" \
  tests/corpora/capstone/aarch64-neon-facge-facgt.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-rounding-halving-add.s.cs" \
  tests/corpora/capstone/aarch64-neon-rounding-halving-add.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-shift-left-long.s.cs" \
  tests/corpora/capstone/aarch64-neon-shift-left-long.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-rounding-shift.s.cs" \
  tests/corpora/capstone/aarch64-neon-rounding-shift.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-saturating-rounding-shift.s.cs" \
  tests/corpora/capstone/aarch64-neon-saturating-rounding-shift.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-saturating-shift.s.cs" \
  tests/corpora/capstone/aarch64-neon-saturating-shift.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-crypto.s.cs" \
  tests/corpora/capstone/aarch64-neon-crypto.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-bitwise-instructions.s.cs" \
  tests/corpora/capstone/aarch64-neon-bitwise-instructions.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-mla-mls-instructions.s.cs" \
  tests/corpora/capstone/aarch64-neon-mla-mls-instructions.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-add-sub-instructions.s.cs" \
  tests/corpora/capstone/aarch64-neon-add-sub-instructions.json --check
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-tbl.s.cs" \
  tests/corpora/capstone/aarch64-neon-tbl.json --check
```

Release Criterion measurement on 2026-09-08:

```sh
cargo bench --bench disasm_decode -- --noplot
```

The original 11-vector branch-family batch measured 12.438 million instructions/second
for Glaurung's native mask dispatch (median 884.39 ns/batch) and 3.735 million
instructions/second through the Capstone adapter (median 2.9451 us/batch), a
3.33x throughput advantage. After expanding the batch to 19 vectors, including
register and test-bit branches, native dispatch measured 10.654 million
instructions/second (median 1.7834 us/batch) versus 2.8331 million through the
adapter (median 6.7064 us/batch), a 3.76x throughput advantage. Criterion's
reported regression compares different batch sizes and is therefore not a
same-work regression. These are family microbenchmarks, not whole-binary speedup
claims; later representation decisions require the real instruction distribution
and adversarial invalid-byte streams described above.

The 27-vector native slice, after adding `adr`/`adrp`, measured 10.861 million
instructions/second (median 2.4860 us/batch) versus 3.0598 million through the
Capstone adapter (median 8.8240 us/batch), a 3.55x throughput advantage. This
uses the renamed `aarch64_native_slice_decode` Criterion group, so it does not
compare unlike batch sizes against the earlier group history.

The 52-vector slice, after adding add/subtract immediate and its `cmp`/`cmn`
aliases, measured 9.3058 million instructions/second (median 5.5879 us/batch)
versus 2.7303 million through the Capstone adapter (median 19.046 us/batch), a
3.41x throughput advantage. The benchmark group now includes its vector count
in its name so Criterion will never label a larger corpus as a same-work
regression again.

The 73-vector slice, after adding scalar unsigned-offset loads/stores, measured
7.8100 million instructions/second (median 9.3469 us/batch) versus 2.0575
million through Capstone (median 35.480 us/batch), a 3.80x throughput advantage.
The lower absolute native rate reflects construction of richer width/access
metadata for memory operands; both backends decoded the identical corpus.

The 77-vector slice, after adding move-wide forms, measured 7.8625 million
instructions/second (median 9.7934 us/batch) versus 2.0058 million through
Capstone (median 38.389 us/batch), a 3.92x throughput advantage.

The 104-vector slice, after adding table-free logical-immediate expansion,
measured 7.3453 million instructions/second (median 14.159 us/batch) versus
2.0505 million through Capstone (median 50.720 us/batch), a 3.58x throughput
advantage.

The 200-vector slice (196 Capstone vectors plus four LLVM test-bit boundaries),
after adding the complete add/subtract extended-register family represented by
the source corpus, measured 6.3111 million instructions/second (median 31.690
us/batch) versus 2.1731 million through Capstone (median 92.035 us/batch), a
2.90x throughput advantage. This family adds 92 active upstream cases spanning
all eight extension kinds, shifts, SP forms, and `cmp`/`cmn` aliases. A separate
reserved `imm3 > 4` encoding verifies fail-closed behavior.

The 273-vector slice, after adding all 73 load/store-pair cases in the source
corpus, measured 5.4194 million instructions/second (median 50.374 us/batch)
versus 2.0817 million through Capstone (median 131.14 us/batch), a 2.60x
throughput advantage. The native forms preserve scalar/vector element widths,
load destinations, store memory access, signed scaled offsets, and the distinct
effective-address behavior of offset, pre-index, and post-index modes. Reserved
signed-word stores and SIMD `opc` encodings are rejected explicitly.

The 417-vector slice, after adding all 144 add/subtract shifted-register cases,
measured 5.2340 million instructions/second (median 79.672 us/batch) versus
1.9773 million through Capstone (median 210.90 us/batch), a 2.65x throughput
advantage. The decoder retains explicit `lsl`/`lsr`/`asr` modifiers, including
`lsr #0` and `asr #0`, and rejects the reserved shift selector and out-of-range
32-bit shift amounts.

The 445-vector slice, after adding all 28 logical shifted-register cases in the
source corpus, measured 5.2752 million instructions/second (median 84.358
us/batch) versus 1.8744 million through Capstone (median 237.41 us/batch), a
2.81x throughput advantage. It covers direct and inverted operations, move and
test aliases, all four shift kinds, and explicit zero shifts. A 32-bit shift of
32 is rejected. An initial run under concurrent load was discarded and repeated
because both backends showed material system-wide slowdown.

The 489-vector slice, after adding all 44 add/subtract-with-carry cases, measured
5.3312 million instructions/second (median 91.724 us/batch) versus 1.8273
million through Capstone (median 267.60 us/batch), a 2.92x throughput advantage.
It covers `adc`/`adcs`/`sbc`/`sbcs` plus the `ngc`/`ngcs` aliases in both widths,
with native destination access and operand widths.

The 521-vector slice, after adding all 32 active conditional-select cases,
measured 5.4920 million instructions/second (median 94.866 us/batch) versus
1.9127 million through Capstone (median 272.39 us/batch), a 2.87x throughput
advantage. Five additional encodings excluded from the active corpus verify
that native canonicalization matches Capstone for `cset`, `cinc`, `csetm`,
`cinv`, and `cneg` aliases.

The 545-vector slice (541 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 24 active conditional-compare cases, measured 4.9562 million
instructions/second (median 109.96 us/batch) versus 1.8317 million through
Capstone (median 297.54 us/batch), a 2.71x throughput advantage. It covers
`ccmp` and `ccmn`, register and immediate operands, both register widths, every
condition represented by the source, and the four-bit fallback NZCV value. The
first measurement showed 18 native outliers under concurrent load and was
discarded; these figures are the repeat measurement over the identical corpus.

The 609-vector slice (605 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 60 scalar multiply cases, measured 5.0361 million
instructions/second (median 120.93 us/batch) versus 1.7277 million through
Capstone (median 352.49 us/batch), a 2.91x throughput advantage. The family
covers 32- and 64-bit `madd`/`msub`, their `mul`/`mneg` aliases, signed and
unsigned widening multiply-add/subtract and aliases, and signed/unsigned
high-half multiply. Native operands retain destination access and the distinct
32-bit multiplicand versus 64-bit result/accumulator widths of widening forms.

The 643-vector slice (639 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 34 active scalar bitfield cases, measured 5.4169 million
instructions/second (median 118.70 us/batch) versus 1.4838 million through
Capstone (median 433.36 us/batch), a 3.65x throughput advantage. It covers
signed/unsigned extraction and insertion, immediate `asr`/`lsl`/`lsr`, and
sign/zero-extension aliases. Native `bfi`/`bfxil` destinations are marked
read-write rather than merely read, and reserved operation, `sf/N`, and 32-bit
immediate combinations fail closed. A repeat run made both backends 32% slower
and was discarded as concurrent system load rather than a same-code regression.

The 683-vector slice (679 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 40 active scalar register-shift, division, one-source, and
extract cases, measured 4.6363 million instructions/second (median 147.32
us/batch) versus 1.5059 million through Capstone (median 453.55 us/batch), a
3.08x throughput advantage. It covers register-controlled `lsl`/`lsr`/`asr`/
`ror`, signed and unsigned division, `rbit`, all width-valid `rev` forms,
`clz`/`cls`, and `extr`. A separate constructed encoding verifies the `extr`
to immediate-`ror` alias, while reserved one-source and invalid extract fields
fail closed.

The 777-vector slice (773 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 94 active scalar unscaled and immediate-writeback load/store
cases, measured 5.1338 million instructions/second (median 151.35 us/batch)
versus 1.6776 million through Capstone (median 463.15 us/batch), a 3.06x
throughput advantage. It covers signed nine-bit offsets, pre-index and
post-index addressing, integer and sign-extending widths, SP bases, and zero
register operands. The native representation preserves register/memory access
and width; valid unprivileged `LDTR`/`STTR` encodings remain explicitly outside
this family and continue to the fallback.

The 817-vector slice (813 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 40 active scalar register-offset load/store cases, measured
4.9595 million instructions/second (median 164.73 us/batch) versus 1.5871
million through Capstone (median 514.78 us/batch), a 3.12x throughput advantage.
The corpus schema now asserts memory base, index, extension, and scale rather
than accepting a flattened string. Native decoding preserves `uxtw`, `sxtw`,
`sxtx`, and `lsl` in lossless text while exposing base/index/scale structurally.
The initial measurement placed native decoding at 281.88 us under transient
load; a repeat moved both backends faster and is the result recorded here.

The 907-vector slice (903 Capstone vectors plus four LLVM test-bit boundaries),
after adding all 90 active scalar SIMD/FP load/store cases, measured 4.7379
million instructions/second (median 191.43 us/batch) versus 1.5786 million
through Capstone (median 574.54 us/batch), a 3.00x throughput advantage. It
covers `b`, `h`, `s`, `d`, and `q` registers across unsigned-offset, unscaled,
pre-index, post-index, and register-offset forms. Native operands retain widths
through 128 bits, load/store access, and structured base/index/scale data while
lossless text preserves `uxtw`, `sxtw`, `sxtx`, and `lsl`; reserved size/opcode
pairs and register-offset options fail closed.

The 966-vector slice (962 Capstone vectors plus four LLVM test-bit boundaries)
adds all 59 active exception-generation, hint, barrier, and exception-return
cases without adding a lookup table. It covers immediate boundary values,
canonical `nop`/`yield`/`wfe`/`wfi`/`sev`/`sevl` aliases, named and numeric
barrier domains, optional `clrex`/`isb` operands, and `eret`/`drps`. Three
release runs measured native medians of 242.01 and 240.47 us/batch on the two
complete runs, while Capstone moved from 619.26 through 686.18 to 727.01
us/batch under changing system load. Native was stable within Criterion's noise
threshold but the oracle was not, so no throughput ratio is claimed for this
slice; the raw measurements are retained to avoid selecting the flattering
run.

The 1,575-vector slice (1,571 Capstone vectors plus four LLVM test-bit
boundaries), after adding all 609 active `MRS`/`MSR` cases, measured 5.9770
million instructions/second (median 263.51 us/batch) versus 1.8979 million
through Capstone (median 829.85 us/batch), a 3.15x throughput advantage. The
346 readable and 258 register-writable rows collapse to 347 named encoding
keys after merging directions and generating four generic `sN_N_cN_cN_N`
spellings algorithmically. The packed index is 2,776 bytes and its deduplicated
name pool is 3,837 bytes: 6,613 bytes total, versus approximately 18,333 bytes
for separate native-width `(u16, &str)` tables with the same unique strings, a
64% logical-payload reduction. Eight-byte entry layout and the sole
direction-dependent `dbgdtrrx_el0`/`dbgdtrtx_el0` alias are pinned by tests.

The 1,633-vector slice (1,629 Capstone vectors plus four LLVM test-bit
boundaries), after adding all 58 active `SYS`/`SYSL`, `AT`, `DC`, `IC`, and
`TLBI` cases, measured 5.7898 million instructions/second (median 282.05
us/batch) versus 1.7343 million through Capstone (median 941.60 us/batch), a
3.34x throughput advantage. Fifty-five named aliases use an eight-byte sorted
entry and reuse the system-register string pool; the complete combined index
and pool occupy 7,377 logical bytes. Raw forms retain both `cN` fields that the
legacy adapter discards. Native aliases also retain their operation name
consistently, while the adapter keeps it only when no general-register operand
is present. Nine native outliers were reported, but the 95% interval was only
281.96--282.14 us and the Capstone run reported no outliers.

The 1,805-vector slice (1,801 Capstone vectors plus four LLVM test-bit
boundaries), after adding 76 scalar floating-point arithmetic/control cases and
96 fixed-point or integer conversion cases, measured 5.6486 million
instructions/second (median 319.55 us/batch) versus 1.7795 million through
Capstone (median 1.0143 ms/batch), a 3.17x throughput advantage. Native reported
three high outliers and Capstone eight; the quoted medians compare the identical
expanded corpus. Four additional malformed conversion encodings pin reserved
FP types, operations, and illegal 32-bit fixed-point scales.

The 1,895-vector slice (all 1,891 active four-byte vectors in the basic
Capstone file plus four LLVM test-bit boundaries), after adding SP `mov` and
`bfc` aliases, CRC32, scalar literal and unprivileged loads/stores, exclusive
and ordered loads/stores, prefetch, FP immediates, and integer-register/lane FP
moves, measured 4.2497 million instructions/second (median 445.91 us/batch)
versus 1.3758 million through Capstone (median 1.3773 ms/batch), a 3.09x
throughput advantage. Criterion reported 13 native and 15 Capstone outliers;
the medians compare the identical corpus. Broader AArch64 MC/regression suites
and architecture extensions remain to be ported.

The 2,387-vector slice adds all 110 GICv3 and 382 trace system-register vectors
without adding opcode branches. Their names are merged into the existing
sorted packed index: 619 eight-byte register entries, 55 eight-byte system
alias entries, and a 6,947-byte deduplicated string pool occupy 12,339 logical
bytes. It measured 6.1546 million instructions/second (median 387.84 us/batch)
versus 1.7267 million through Capstone (median 1.3824 ms/batch), a 3.56x
throughput advantage. No outliers were reported. The lower absolute median
than the preceding, smaller run reflects a fresh release build and machine
conditions; only the matched backends within this run are compared.

The 2,399-vector slice adds every vector from the scalar absolute and negate
files: integer `abs`/`neg`, all four element widths of saturating
`sqabs`/`sqneg`, and single/double `fabd`. Compact field decoding handles the
whole class and explicitly rejects illegal element sizes. It measured 6.0536
million instructions/second (median 396.29 us/batch) versus 1.8945 million
through Capstone (median 1.2663 ms/batch), a 3.20x throughput advantage. No
outliers were reported.

The 2,403-vector slice adds scalar `add`/`sub` and `sshl`/`ushl`, sharing one
three-register field decoder and rejecting every non-64-bit scalar encoding in
those classes. Two measurements found changing host load: the first measured
native/Capstone medians of 397.26 us/1.7365 ms, while the repeat measured
530.60 us/1.5125 ms. Because the backends moved in opposite directions by
material amounts, no throughput ratio is selected for this slice.

The 2,405-vector slice adds integer and floating scalar pairwise addition. The
importer and native decoder represent `vN.2d` as register `vN` plus a two-lane,
64-bit-element shape, with a 128-bit total operand width; the encoding decoder
also admits the architectural single-precision `faddp` form and rejects
reserved sizes. It measured native/Capstone medians of 453.00 us/1.2652 ms.
Capstone reported 33 outliers and preceding measurements showed material host
variation, so no ratio is selected from this run.

The 2,447-vector slice adds all 42 vectors from the scalar saturating-add/sub,
saturating-shift, saturating-rounding-shift, and rounding-shift files. One
mask/field decoder now covers `sqadd`/`uqadd`, `sqsub`/`uqsub`, mixed-sign
`suqadd`/`usqadd`, `sqshl`/`uqshl`, `sqrshl`/`uqrshl`, and 64-bit
`srshl`/`urshl`; the latter rejects non-64-bit scalar encodings. It measured
native/Capstone medians of 601.50 us/2.4733 ms. Native reported 14 outliers and
the host had already shown material run-to-run variation, so no throughput
ratio is selected.

The 2,458-vector slice adds all 11 vectors from the scalar integer comparison
file: `cmeq`, `cmhs`, `cmge`, `cmhi`, `cmgt`, `cmle`, `cmlt`, and `cmtst`,
including the compare-with-zero encodings. The decoder shares masks and fields
with the existing scalar three-register path, rejects non-64-bit encodings and
the reserved unsigned `cmlt`-zero form, and works around a capstone-rs 0.12
detail-union artifact that reports the textual `#0` operand twice. One matched
run measured native/Capstone medians of 415.85 us/1.2799 ms (3.08x), with two
and four mild high outliers respectively. Because earlier runs on this host
varied materially, this is retained as a matched-run result rather than a
stable platform-wide speedup estimate.

The 2,478-vector slice adds all 20 vectors from the scalar floating-point
comparison file: register and zero forms of `fcmeq`, `fcmge`, and `fcmgt`, zero
forms of `fcmle` and `fcmlt`, and register forms of `facge` and `facgt`, across
single and double precision. The importer first failed closed at 14/20 vectors
until shared register/zero mnemonic selection was made exhaustive. A matched
run measured native/Capstone medians of 624.68 us/1.8205 ms, but native reported
21 outliers (ten severe) and a wide interval, so no throughput ratio is selected
from this run.

The 2,487-vector slice adds all nine vectors from the scalar extract-and-narrow
file: `sqxtn`, `uqxtn`, and signed-to-unsigned `sqxtun` for 16-to-8,
32-to-16, and 64-to-32-bit narrowing. One decoder derives the source width from
the destination-size field and rejects the reserved widest destination and
non-U `sqxtun` encodings. A matched run measured native/Capstone medians of
430.45 us/1.2964 ms (3.01x); Capstone reported three severe high outliers, and
the host remains variable across runs, so this is not promoted to a stable
platform-wide speedup estimate.

The 2,497-vector slice adds all ten vectors from the scalar reciprocal file:
single/double `frecps`, `frsqrts`, `frecpe`, `frecpx`, and `frsqrte`. Register
width is decoded from the shared precision bit while the neighboring opcode bit
selects reciprocal versus reciprocal-square-root operations. Four constructed
invalid encodings pin reserved U and size combinations. The vectors are included
in the count-keyed Criterion workload; a new standalone ratio is deferred until
another matched run is useful rather than treating every small corpus increment
as an independently stable performance population.

The 2,509-vector slice adds all 12 vectors from the scalar multiply file:
`sqdmulh`, `sqrdmulh`, `fmulx`, `sqdmlal`, `sqdmlsl`, and `sqdmull`. A single
mask/field decoder handles equal-width and widening destinations, marks the two
accumulating destinations `ReadWrite`, and rejects reserved byte/double size and
U combinations. Five constructed invalid encodings supplement the complete MC
file. These vectors join the same count-keyed Criterion workload rather than
creating a new performance population for a 12-vector increment.

The 2,521-vector slice adds all 12 vectors from the scalar by-element multiply
file: single/double `fmul` and `fmulx` across every legal indexed lane. The
native operand carries the selected vector register, one-element S/D shape, and
lane index as separate structured fields. The importer now parses indexed
B/H/S/D operands generically instead of its former D-only special case. Two
constructed invalid encodings pin reserved size and double-precision L-bit
combinations.

The 2,533-vector slice adds all 12 vectors from the scalar by-element
multiply-accumulate file: single/double `fmla` and `fmls` across every legal
indexed lane. These operations extend the existing by-element mask dispatch,
vector/lane extraction, and validity checks rather than duplicating them; their
destination operands are `ReadWrite`. Constructed tests reject the reserved U
encoding and the double-precision form with its L bit set. A matched full-slice
run measured native/Capstone medians of 780.68 us/2.4203 ms, but reported 15
native and 20 Capstone outliers, so no throughput ratio is selected.

The 2,547-vector slice adds all 14 vectors from the scalar by-element
saturating multiply-accumulate file: `sqdmlal` and `sqdmlsl` for halfword and
single-word indexed sources. The native decoder distinguishes the halfword
form's H:L:M lane index from the single-word form's H:L index, widens the
destination to S/D, marks it `ReadWrite`, and fails closed on U and reserved
size combinations. These vectors are included in the existing count-keyed
Criterion workload; the preceding 2,533-vector matched run remains the latest
reported timing because this increment is too small to justify treating it as
a new performance population.

The 2,564-vector slice adds all 17 vectors from the scalar by-element
saturating multiply file: widening `sqdmull` and equal-width `sqdmulh` and
`sqrdmulh`. It reuses the indexed halfword/single-word extraction path while
selecting the destination width from the operation. Three constructed invalid
encodings cover U, byte-source, and double-source reservations. The vectors
join the count-keyed Criterion workload; no standalone ratio is inferred from
this small increment.

The 2,586-vector slice adds all 22 active rows from the scalar `dup` MC file,
including its repeated eleven-vector block. Capstone renders the scalar-copy
alias as `mov`; native decoding derives the B/H/S/D element width from the
lowest set bit of `imm5` and the lane from its remaining high bits, avoiding a
lookup table. Invalid tests reject zero and reserved 128-bit element selectors.
The repeated upstream rows remain in the QA corpus so importer completeness is
line-for-line rather than silently deduplicated.

The 2,619-vector slice adds all 33 scalar conversion vectors: signed/unsigned
integer-to-float, every tested floating rounding mode, fixed-point immediate
forms, and narrowing `fcvtxn`. Fixed-point widths and fractional-bit counts are
derived directly from the immediate prefix rather than table entries. Precise
conversion dispatch now precedes broad unary/reciprocal masks; this corrected
an older false-invalid classification for an encoding that is valid `scvtf`.
Constructed invalid cases cover empty and undersized fixed-point prefixes.

The 2,660-vector slice completes the scalar-NEON file tranche with all 41
immediate-shift vectors. One arithmetic decoder derives element width from the
highest set immediate-prefix bit, then computes left or right shift counts
algebraically. It covers signed/unsigned, rounding, accumulating, saturating,
insert, and narrowing variants while preserving `ReadWrite` destinations for
accumulate/insert operations. Invalid cases exercise empty prefixes, reserved
signed opcode forms, and an illegal 64-bit narrowing destination.

The 2,662-vector slice starts the vector-NEON tranche with both 64- and 128-bit
`ext` rows. A single Q-controlled shape selects 8B or 16B operands and accepts
the full legal byte-index range; an adversarial 8B index-eight encoding fails
closed. Native preserves the destination write while the differential harness
normalizes Capstone's legacy all-read vector-access metadata.

The 2,668-vector slice adds all six vector reciprocal-step rows: `frecps` and
`frsqrts` over 2S, 4S, and 2D shapes. One Q/size decoder produces all three
legal arrangements and rejects the reserved 1D form. It shares structured
vector operands with `ext` rather than importing Capstone's per-instruction
operand tables.

The 2,678-vector slice adds all ten pairwise-add rows. Integer `addp` covers
8B/16B, 4H/8H, 2S/4S, and 2D; floating `faddp` covers 2S/4S and 2D. The decoder
derives lane count from Q and element width and rejects both reserved 1D forms,
using one structured three-vector operand path for integer and floating cases.

The 2,690-vector slice adds all twelve absolute floating-compare rows, including
the upstream file's duplicated six-vector block. `facge` and `facgt` share the
same 2S/4S/2D arrangement helper now used by reciprocal-step and floating
pairwise operations, reducing duplicated Q/size logic. The reserved 1D shape
fails closed, while line-level importer completeness retains duplicate QA rows.

The 2,702-vector slice adds all twelve signed/unsigned rounding-halving-add
rows over 8B/16B, 4H/8H, and 2S/4S. A shared integer arrangement helper now
derives vector shape for both this family and integer pairwise add; it rejects
the reserved double-element encoding before operand construction.

The 2,714-vector slice adds all twelve signed/unsigned shift-left-long rows,
including lower- and upper-half forms. Element width and shift count come from
the immediate prefix; destination width doubles algebraically, while Q selects
the source's lower or upper half and the `*2` mnemonic. Empty and 64-bit source
prefixes fail closed, avoiding per-arrangement decode tables.

The 2,728-vector slice adds all fourteen signed/unsigned vector rounding-shift
rows over every legal B/H/S/D arrangement. These join rounding-halving add in a
single direct-mask "integer three-same" decoder, with per-opcode maximum element
size controlling validity. The reserved single-lane 1D encoding fails closed.

The 2,742-vector slice adds all fourteen signed/unsigned saturating rounding
shifts (`sqrshl`/`uqrshl`) over the same complete arrangement set. They extend
the shared integer-three-same mask dispatch with two opcode values rather than
new operand logic; the reserved 1D form is independently pinned as invalid.

The 2,756-vector slice adds all fourteen signed/unsigned saturating variable
shifts (`sqshl`/`uqshl`) over every legal B/H/S/D vector arrangement. Two new
direct-mask cases reuse the same integer-three-same shape and operand path;
there is no per-arrangement table. The 64-bit vector's reserved single-lane 1D
encoding is pinned invalid, and the complete upstream file participates in
both provenance/completeness and Capstone differential gates.

The 2,770-vector slice completes the fourteen-row AES/SHA crypto MC file.
Seven exact two-register masks and seven three-register opcode values share a
single field decoder, with register numbers extracted algebraically rather
than represented as instruction records. Native operands distinguish the
destructive AES round and SHA schedule/hash destinations from pure-write AES
mix-column destinations; the legacy Capstone comparison normalizes only the
adapter metadata it cannot expose.

The 2,786-vector slice completes all sixteen vector bitwise rows: `and`, `bic`,
`orr`, `orn`, `eor`, `bsl`, `bit`, and `bif` in both 8B and 16B forms. Eight
opcode masks share one field path, Q alone determines shape, and `bsl`/`bit`/
`bif` retain their destructive destination access. The architecturally
canonical `orr Vd, Vn, Vn` to `mov Vd, Vn` alias is tested separately with
non-corpus register numbers against Capstone.

The 2,804-vector slice completes all eighteen integer and floating vector
multiply-accumulate/subtract rows. Integer `mla`/`mls` extend the shared
three-same arrangement decoder through B/H/S shapes; `fmla`/`fmls` use the
common legal 2S/4S/2D shape derivation. Every destination is structurally
`ReadWrite`, and constructed 1D encodings independently pin the integer and
floating reserved cases as invalid.

The 2,824-vector slice completes all twenty vector add/subtract rows. Integer
`add`/`sub` extend the same three-same field decoder through every legal
B/H/S/D arrangement; floating `fadd`/`fsub` share the compact FP three-same
path over 2S/4S/2D. Constructed q=0 double-element words pin both integer and
floating 1D forms as invalid. The unsupported-family sentinel moves onward as
each formerly unsupported family is promoted.

The 2,844-vector slice completes all twenty `tbl`/`tbx` table-lookup rows for
8B and 16B indices. The decoder derives one-to-four-member table lists from the
length and first-register fields, including modulo-32 wraparound. Glaurung now
represents those lists as first-class structured operands with ordered register
names and a V.16B member shape instead of flattening them into presentation
text. Q still controls the destination and index shape, and `tbx` retains its
destructive `ReadWrite` destination. Differential comparison flattens lists
only at the legacy Capstone-adapter boundary; the provenance corpus separately
asserts the richer native structure.

## 2026-09-08 wrap-up and resume point

This workstream is deliberately paused, not complete. The checked-in native
slice covers 2,840 of 4,405 active vectors in the pinned Capstone AArch64 MC
directory (64.47%) and 38 of its 57 files. Against the 17,935-vector pinned MC
estate across the five architecture families in scope, it covers 15.83%.
Within AArch64, all 21 scalar-NEON files are complete and 14 of 33 vector-NEON
files are complete. Four additional LLVM branch-boundary cases bring the live
differential population to 2,844. These are corpus coverage figures, not ISA
completeness figures: no architecture backend has yet met the promotion gate
for removing its production fallback.

What exists now:

- A production-first AArch64 hybrid decoder with explicit unsupported versus
  malformed results, compact mask/field family decoders, and Capstone fallback.
- A provenance-preserving importer for Capstone `.s.cs` files, checked JSON
  corpora, structured operand assertions, invalid-encoding tests, and a live
  native-versus-Capstone differential oracle.
- Table-free logical-immediate expansion, algebraic arrangement decoding, a
  packed system-register/name index, and first-class register-list operands.
  This is a Rust re-expression of behavior and data, not a transliteration of
  Capstone's generated C tables.
- A safe dependency-free `no_std` `glaurung-disasm` nucleus that compiles for
  `wasm32-unknown-unknown`. The full decoder, root crate, and Glaurung product
  do not yet build for WASM.
- Count-keyed Criterion infrastructure and early same-corpus measurements.
  The most recent recorded benchmark predates much of the present 2,844-case
  slice and must not be quoted as current whole-decoder performance.

The next bounded AArch64 increment is
`suite/MC/AArch64/neon-shift.s.cs` (21 active vectors). The other 18 unfinished
vector-NEON files, in increasing source-corpus size, are:
`neon-mul-div-instructions.s.cs` (23), `neon-halving-add-sub.s.cs` (24),
`neon-aba-abd.s.cs` (27), `neon-saturating-add-sub.s.cs` (28),
`neon-max-min-pairwise.s.cs` (36), `neon-max-min.s.cs` (36),
`neon-across.s.cs` (39), `neon-simd-copy.s.cs` (41), `neon-perm.s.cs` (42),
`neon-mov.s.cs` (69), `neon-simd-post-ldst-multi-elem.s.cs` (106),
`neon-2velem.s.cs` (112), `neon-simd-ldst-one-elem.s.cs` (128),
`neon-compare-instructions.s.cs` (135), `neon-3vdiff.s.cs` (142),
`neon-simd-shift.s.cs` (150), `neon-simd-ldst-multi-elem.s.cs` (196), and
`neon-simd-misc.s.cs` (210). After vector NEON, AArch64 still needs a formal
architecture/mode/extension/family manifest, coverage outside this pinned MC
directory, fuzzing, decoder extraction across the WASM seam, and fallback
removal. ARM/Thumb, MIPS, PowerPC, and RISC-V remain production Capstone
backends; x86 remains an Iced backend and is a later replacement decision.

Resume with:

```sh
export TMPDIR="$HOME/.cache/glaurung/tmp"
export CAPSTONE_SOURCE="$HOME/.cache/glaurung/sources/capstone-rs-0.12.0/capstone-sys/capstone"
mkdir -p "$TMPDIR"
uv run python tools/import_capstone_mc.py \
  "$CAPSTONE_SOURCE/suite/MC/AArch64/neon-shift.s.cs" \
  tests/corpora/capstone/aarch64-neon-shift.json
```

At this stop point, the TBL/TBX slice has passed `uv run maturin develop`, the
11 focused native-AArch64 tests, all 15 core-instruction tests, the importer
reproduction and Python syntax checks, both disassembly integration tests, and
the WASM target check recorded below, and the full
`cargo test --features python-ext` gate (4,690 library tests plus integration
binaries). A full Python-suite attempt was stopped after 673 passes and 10
decompiler/source-recovery failures unrelated to the decoder paths in this
lane; it did not produce a green full-suite claim. A fresh expanded benchmark
was not run before this handoff was written.
The checkout is shared and contains concurrent unrelated edits; no commit or
push was requested or performed. Continue to stage explicit owned paths only.

Portable ISA primitives now live in the safe, dependency-free, `no_std`
`crates/glaurung-disasm` crate. AArch64 signed scaled-field expansion and the
table-free logical-immediate algorithm, plus the packed bidirectional system-
register index, are consumed by the production native backend from that crate.
Its tests include reserved encodings, representative masks, signed branch-field
boundaries, the system-register direction alias/layout, and an exhaustive
invariant check over the logical-immediate field space. On 2026-09-08 both of
these passed:

```sh
cargo test --manifest-path crates/glaurung-disasm/Cargo.toml
cargo check --manifest-path crates/glaurung-disasm/Cargo.toml \
  --target wasm32-unknown-unknown
```

This establishes a real WASM-capable decoder nucleus. The root crate still
contains Python bindings, native binary-loading integrations, and Capstone
fallbacks, so it is intentionally outside the present WASM claim.
