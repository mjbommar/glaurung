# Decompiler defect register — 2026-08-05

This is the authoritative execution checklist for the measured decompiler
defects preserved on 2026-08-05. It is a live evidence register: an item is
closed only when its root cause is fixed at the responsible layer, its named
canaries pass, relevant broad gates pass, and the evidence below is current.

## Scope provenance

The path named by the work request was absent from the current checkout, every
local branch, and every listed worktree when execution began. The same dirty
checkout contained `docs/design/backlog-2026-08-05.md`, explicitly described as
eight open, real, measured defects preserved from the task list. This register
reconstructs those eight items without broadening or dropping them. If an older
copy of this register is recovered, reconcile it item by item before declaring
the overall register complete.

## Status vocabulary

- **OPEN** — reproduced or evidenced, but no accepted fix exists.
- **ADJUDICATE** — the current oracle is insufficient; obtain authoritative
  evidence before changing behavior.
- **IN PROGRESS** — owned implementation work exists but required proof is not
  complete.
- **FIXED / GATES PENDING** — focused proof is green; a named broad gate remains.
- **CLOSED** — implementation, regression, broad validation, and register
  evidence are all complete.

Focused tests, a rebuilt extension, fixture behavior, the full local gate, and
remote/integrated state are separate evidence. One never implies another.

## Register summary

| ID | Defect | Status | Primary owner/lane |
|---|---|---|---|
| D-001 | Phi-copy widths collapse distinct bare-name definitions | CLOSED | `agent/defect-register` |
| D-002 | Optimized large-function extents are wrong | CLOSED | adjudicated on `agent/defect-register` |
| D-003 | AAPCS outgoing stack arguments stop at repeated slots | CLOSED | `agent/defect-register` |
| D-004 | Large ARM table dispatches do not structure | CLOSED | `agent/defect-register` |
| D-005 | Wrapped 32-bit array indices render as huge unsigned values | CLOSED | `agent/defect-register` |
| D-006 | C++ recovery lags across i386, AArch64, and ARMv7 | CLOSED | `agent/defect-register` |
| D-007 | Six ARMv7 `getent` string/call discrepancies lack a trustworthy mode oracle | CLOSED | adjudicated on `agent/defect-register` |
| D-008 | x86 ZF is computed from an untruncated parent register | CLOSED | `agent/defect-register`; `agent/x86-flags` remains separate BSR/BSF work |

## D-001 — per-definition phi-copy width attribution

**Observed defect.** Phi-copy coalescing keeps a compatibility
`HashMap<VReg, u8>`. A kept-bare ABI name can have several definitions, so the
last definition overwrites the earlier widths. Replaying that one width for
every definition either refuses ordinary phis or, worse, permits a mixed-width
class.

**Required fix.** Preserve width per `InstrAddr`, map it to the exact
`SsaValue { base, version }`, and attach that width to the corresponding phi
incoming edge. Do not treat an unproven version-zero live-in as harmless width
evidence.

**Canaries.**

- mixed 32/64-bit definitions sharing bare `rax` remain ambiguous globally;
- a phi edge uses the width of its actual reaching bare definition rather than
  unrelated definitions of the same register;
- `11_call_shapes:gcc:O2:call_chain_in_loop` calls `signed_step(v)`, not
  `signed_step(seed)`; and
- `factorial_while` does not acquire a 32-bit declaration for a 64-bit product.

**Current evidence (2026-08-05, branch `agent/defect-register`).**

- RED: `kept_bare_definition_widths_are_not_collapsed_by_name` returned
  `Known(8)` where `Ambiguous` was required.
- GREEN: all 35 `ir::value_number::tests` pass, including a real GCC `-O2`
  build of `11_call_shapes.c` proving the call argument has entry and backedge
  definitions.
- Fresh release extension: complete `11_call_shapes` slice passed (52 function
  verdicts across GCC/Clang O0/O2); `@smoke` passed.
- Complete Rust suite passed: 1,734 library tests, all integration tests, and
  doctests (one documented ignored doctest), with exit status 0.
- Current-system `/usr/bin/grep` attribution measurement across 21,635 attempts:
  width refusals 4,146 -> 4,137. Exact edge identity also exposed 18 additional
  interference conflicts, so total merges 10,937 -> 10,921. This is a soundness
  correction, not evidence for a large cosmetic merge-rate gain.
- The older 4,033-attempt/46%-width corpus artifact is not present, so that exact
  historical number is not yet replayable.
- The first full five-lane local gate after D-008 passed Rust, the x86-64
  structural/behavioral matrix, all cross-architecture round trips, and both
  executable DecBench corpora. Its metric lane reported five values requiring
  adjudication rather than silently accepting them.
- Three GED deltas are not branch regressions. A detached worktree at the
  exact base object `fcca960bd7490c452a541f1034d13f2dd4e98eda` reproduced all
  three current scores, and each generated C artifact was byte-identical to the
  branch artifact (SHA-256 `35f453e0...`, `210cb1b8...`, and `7a2e5da9...`).
  The committed baseline was stale relative to its own base commit and current
  evaluator: `linkedlist:{clang,gcc}:O2` GED is 2.5 rather than 0 and
  `matrix:clang:O2` GED is 24 rather than 21.
- The other two deltas were traced across immutable intermediate commits.
  `linkedlist:clang:O0` byte match 0.47 -> 0.10 already exists before D-008 and
  accompanies a structurally closer recovery: direct recovered `node` fields,
  fewer spilled pointer locals, GED 0, and green behavior. `strops:gcc:O2` byte
  match 0.42 -> 0.35 begins exactly at D-008 because the sound width fix emits
  explicit byte-width casts; GED remains 7.67, type match remains 0.61, and the
  behavior oracle remains green.
- Exactly those five reviewed values were regenerated. A fresh complete
  56-cell metric check then passed with no per-cell regressions. No other
  baseline value changed.

The unavailable historical 4,033-attempt corpus is recorded as an archival
limitation rather than a hidden gate. The current 21,635-attempt attribution
measurement, exact canaries, immutable-base replay, and full ratchet now provide
the reproducible closure evidence.

## D-002 — optimized large-function extent

**Observed defect.** `openssh:sshbuf_fromb` produces roughly 257 lines/40 gotos
for a small source function and scores GED 202. Approximately twenty large
functions dominate aggregate GED; the largest five exceed the full measured gap
to Ghidra.

**Required investigation.** Compare symbol/DWARF/unwind ranges, discovered
chunks, CFG ownership, tail calls, cold splits, and the bytes actually lifted.
Determine whether discovery overextends the function or whether the lifter
imports blocks outside authoritative chunks. Preserve current completeness
telemetry.

**Acceptance.** A real optimized OpenSSH fixture has an authoritative byte/block
ownership proof; adjacent functions/cold chunks remain separate; behavioral and
CFG-completeness controls pass; improvement is not inferred from GED alone.

**Adjudication and closure evidence (2026-08-05).** The proposed extent root
cause is false for the named canary. The official OpenSSH portable 9.1p1 source
was rebuilt at `-O2 -g -fno-builtin -save-temps=obj`; `--without-openssl` was
used only to avoid OpenSSH 9.1p1's configure rejection of host OpenSSL 3.5.

- ELF `STT_FUNC` says `sshbuf_fromb` starts at `0xb5e0` and is `0x3a9` (937)
  bytes. DWARF independently gives `low_pc=0xb5e0`, `high_pc=0xb989`, and its
  FDE covers exactly `0xb5e0..0xb989`.
- The next symbol, `sshbuf_reset`, starts at `0xb990`; the seven-byte gap is
  alignment padding, not an owned adjacent body or cold chunk.
- Current Glaurung discovery reports entry `0xb5e0`, size 937, 52 blocks, and
  88 edges with neither per-function nor total truncation. The decompiler exits
  successfully under the authoritative-range verifier, and its last recovered
  block labels remain below `0xb989`.
- The large native body is real: GCC inlines repeated `sshbuf_check_sanity`,
  `sshbuf_len`, `sshbuf_ptr`, and `sshbuf_set_parent` logic, then emits the
  configured `-fzero-call-used-regs=all` return epilogues. The retained DecBench
  sample shows the same expansion in every backend; angr/IDA/Ghidra/Binary
  Ninja/Kuna/Phoenix GED values are all high (150--233).

No extent code was changed. Treating source line count or GED as a byte-range
oracle here would truncate valid compiler-generated control flow.

## D-003 — AAPCS outgoing stack arguments

**Observed defect.** `call_into_spill` recovers too few arguments for the
eight-argument call. `fold_one_call` breaks when it encounters a second write to
an already claimed ABI slot, while `mark_arg_reads_in_stmt` marks r2/r3 as read
before stack slots are recognized.

**Required fix.** The shared backward scan must distinguish already-consumed
stack-setup statements from real clobbers and handle repeated slots without
weakening the x86-64 path. Do not special-case the fixture.

**Canaries.** AAPCS core/stack split, repeated-slot overwrite, intervening real
read/clobber, x86-64 stack arguments, and real `call_into_spill` behavior across
available architectures.

**Current evidence (2026-08-05, branch `agent/defect-register`).** The defect
had three coupled owners rather than one fixture-local break:

- authoritative DWARF types for the eight integer parameters of
  `spill_combine` retained heuristic VFP live-ins and produced the impossible
  layout `[r0,r1,r2,r3,s0,s1,s2,s3]`;
- the shared backward scan did not recognize interleaved 4-byte AAPCS stores at
  `[sp,#0..12]`, so those stores marked r2/r3 as intervening reads; and
- the immediately preceding `signed_step` result remained spelled as bare r0
  inside transitive temporaries, allowing final role naming to turn `r + N`
  back into `arg0 + N`.

RED regressions captured all three failures. Locked scalar declarations now
project source-ordered AAPCS storage, using explicit `argN` roles once the core
bank is exhausted. Call reconstruction accepts only the exact integer layout
`r0..r3,arg4..argN` and one nearest, contiguous 4-byte outgoing area; calls,
control boundaries, stack-pointer writes, unrelated stores, duplicates, and
gaps reject it. Proven stack stores are excluded from the register read scan,
read-before-call SSA definitions remain statement-rooted, shadowed older r2/r3
definitions no longer terminate the scan, and a preceding call result receives
one exact identity across the proven straight-line setup window.

- all 71 `ir::call_args::tests` and all 51 `ir::types_recover::tests` pass;
- the complete Rust suite passes: 1,738 library tests, every integration test,
  and doctests (one documented ignored doctest), with exit status 0;
- the negative AAPCS oracle refuses to combine stack slots across an intervening
  call, while existing SysV stack/cleanup and read/clobber controls remain green;
- a fresh release extension renders the real ARMv7 O0 and O2 calls with exactly
  eight ordered arguments; and
- the complete `11_call_shapes` architecture matrix preserves every prior
  x86-64/i386/AArch64 verdict while ARMv7 `call_into_spill` improves from fail
  to pass at both O0 and O2.

**Closure.** The final full Python and five-lane decompiler gates pass with the
complete register applied; the reviewed metric ratchet passes 56/56 cells.
Mixed VFP/core calls which themselves spill remain deliberately fail-closed
until the call layout owns explicit stack locations.

## D-004 — large ARM dispatch structuring

**Observed defect.** Betaflight's 240-arm dispatch is decoded, but
`switch_arm_build_order` rejects arms with predecessors outside the selected arm
set (shared error exits and a second table branch). NuttX `bin_170` has a clean
guard/table/bound but its arms do not attach, possibly due to extent clipping.

**Required fix.** Separate dispatch target completeness from region ownership.
Represent shared exits/secondary dispatches explicitly and prove case-region
boundaries; use goto fallback when proof fails. Do not simply waive the external
predecessor check.

**Acceptance.** Exact target sets remain intact; the 240-arm switch and nested
dispatch have structural accounting proof; shared exits execute correctly; the
NuttX case is independently root-caused; broad ARM and control gates pass.

**Current evidence (2026-08-05, branch `agent/defect-register`).** Both proposed
root causes were too coarse. Discovery and lifting already retain the complete
dispatches and extents. Two later ownership/accounting defects independently
forced the lossless labelled-CFG fallback:

- NuttX O2-noinline `nxsig_find_pendingsignal` (`bin_170.elf`, SHA-256
  `e3bc6f47bb8e792b0aa5ca16bffedcea2812f8f2764a15ae7c0547f02f4c8944`)
  has 22 blocks in the authoritative `0x800d724..0x800d7e6` range. Its guard at
  `0x800d746` and dispatch at `0x800d752` both reach the formal default at
  `0x800d766`; every explicit case reaches that shared suffix as well. Building
  cases first marked the suffix visited, then produced an empty formal default
  and dropped the guard edge.
- Betaflight O2 `mspProcessInCommand` (`bin_166.elf`, SHA-256
  `42ffb92f561e384a536eb72ad741583c0727c6adb5779ac7e1a0969ec74972ec`)
  has 393 blocks in the authoritative `0x8028164..0x8029e06` range. Raw region
  recovery preserved the 240-slot dispatch at `0x802818c`, its ten-slot nested
  dispatch at `0x802839a`, and a four-slot dispatch at `0x8029d10`. Production
  nevertheless rejected the tree because accounting treated an explicit
  `0x8029dce -> 0x802837a` jump from inside a loop as if it also fell through
  to the loop header at `0x80299f4`, inventing a nonexistent edge.

The guarded-switch builder now constructs its formal default with borrowed
ownership, matching the existing unguarded-switch rule. Shared reachability is
therefore represented without waiving the arm predecessor proof. Structural
accounting now distinguishes explicit non-latch loop exits from actual jumps to
the loop header; only the latter imply a latch. RED regressions preserve both
real reduced shapes.

- all 53 `ir::structure::tests` and all 18
  `ir::structure_accounting::tests` pass;
- a fresh release extension renders NuttX with cases 0--6 and 9 plus an explicit
  default, and no unrecovered indirect jump;
- the same extension renders all three Betaflight switches, including 56
  non-default destinations from the intact 240-slot outer target table and five
  from the ten-slot nested table, with no unrecovered indirect jump; and
- Betaflight accounting retains only `BlockDuplicated` and `EdgeViaGoto` quality
  findings. No `BlockDropped`, `EdgeUnaccounted`, `BackEdgeUnowned`,
  `ImpliedEdgeAbsent`, `GotoTargetMissing`, or `SwitchArmOutsideLoop` finding
  remains.

**Closure.** The final full Python and five-lane decompiler gates pass. The
architecture lane matches its complete baseline exactly, including all ARM
controls, and both executable behavior corpora remain green.

## D-005 — wrapped 32-bit array-index rendering

**Observed defect.** i386 `heat_step_1d` renders `source[i - 1]` as
`arg1[local_14 + 0x3fffffff]`. The value is correct modulo 32 bits but becomes a
4-GiB out-of-bounds access when the emitted C is rebuilt under LP64.

**Required fix.** Find the upstream fold that factors `k*S + C` into an array
index. With a proven 32-bit pointer width, normalize the quotient into
`[-2^31/S, 2^31/S)`. Preserve `0x3fffffff` on a genuine LP64 target.

**Canaries.** Real GCC `-m32 -O0` `heat_step_1d`, positive/negative wrapped
offsets, non-divisible offsets, non-power-of-two element sizes, and LP64
same-bits negative control. The portable rebuild must execute safely.

**Current evidence (2026-08-05, branch `agent/defect-register`).** The fault was
at the exact factoring boundary: `try_array_index` proved
`base + index*sizeof(T)` and the renderer removed the byte scale, but it did not
carry the target pointer width into the resulting C array index. GCC i386's
`0x3fffffff * 4 == -4 (mod 2^32)` consequently became an ordinary positive LP64
index after the scale disappeared.

The shared array-access renderer now reconstructs the signed 32-bit byte
residue first and divides it by the exact access size. It rewrites only a direct
constant term in a proven scaled index, refuses a residue not divisible by the
element size, and leaves every non-ILP32 render unchanged. Loads and stores use
the same path; this is necessary because the real fixture's final copy reads
and writes the same wrapped index.

- RED/GREEN unit canaries cover positive and negative wrap, a wrapped store,
  exact non-power-of-two scale 6, refusal of a non-divisible scale-3 residue,
  and an LP64 same-bits control;
- all 144 `ir::ast::tests` pass;
- a fresh release extension decompiles the real GCC 15.2 `-m32 -O0`
  `heat_step_1d` (`0x113d`, fixture SHA-256
  `864fe7147bdb2f2c68b30e73e74855b454e61ca68ad218bf4cb9731e5806163c`)
  with `arg1[local_14 - 1]` and
  `arg0[arg2 - 1] = arg1[arg2 - 1]`; no `0x3fffffff` remains; and
- the Docker-backed 32-case execution differential passes both the i386 O0
  canary and its x86-64 O0 control.

**Closure.** The final full Python and five-lane decompiler gates pass. The
architecture lane executes the ILP32 target-ABI canary and matches its complete
baseline exactly; the 56-cell metric ratchet is green.

## D-006 — C++ recovery across architectures

**Observed matrix.** x86-64 is 5/5 at O0/O2. i386 is 1/5 O0 and 4/5 O2;
AArch64 is 3/5 O0 and 2/5 O2; ARMv7 is 0/5 O0 and 4/5 O2.
`cpp_exception` fails every non-control lane at both optimization levels, while
ARMv7's O0-wide failure indicates an O0 shape issue rather than one generic
Itanium-ABI defect. Forty mangled functions per lane remain structural-only.

**Required work.** Cluster failures by root cause (EH extent/landing pads,
constructors/destructors, vtables, hidden `this`, sret, calls, or rendering) and
fix one architecture-neutral semantic cause at a time. Do not collapse all
failures into one C++ heuristic.

**Acceptance.** Every five-function lane has real execution verdicts; previously
passing cells stay green; structural-only functions are either executed or
explicitly justified; exact and broad C/C++ gates are reported separately.

**Root causes and current evidence (2026-08-05, branch
`agent/defect-register`).** The original matrix conflated real recovery defects
with an invalid execution oracle. In particular, `cpp_exception` already passed
every non-control cell when replayed; the older all-red statement was stale.
Four independently proved causes were addressed:

- AArch64 `LDP`/`STP` hard-coded eight-byte elements and strides even for `wN`
  register pairs. A RED lift test recovered two eight-byte accesses at offsets
  0 and 8 from `stp w3, w1, [x0]`; the lifter now derives pair width and stride
  from the decoded scalar operand, producing four-byte accesses at 0 and 4.
- AArch64 O0 lambda captures described by DWARF relative to call-frame CFA were
  ignored, while globally rebasing every SP-relative access caused a real
  merge-sort regression. CFA objects now use the architectural entry-SP
  coordinate only when a bounded seeded object actually contains the access.
  Debug extents and adjacent indexed partitions provide that bound; a final
  conservative "to the frame base" partition does not. When an address alias
  proves the object after an earlier scalar initializer, the equivalent
  current-SP slot metadata migrates into the object so initialization and
  escape remain one storage identity. The exact AArch64 O2 `merge_sort_i32`
  cell is green with this proof gate.
- i386/ARMv7 C++ wrappers were being recovered from ILP32 and then executed as
  LP64 C against LP64 helper objects. Pointer fields and aggregate layouts made
  those crashes harness artifacts. The cross-architecture gate now builds a
  dependency-free target C worker, rebuilds the recovery for its source ABI,
  loads the original target object beside it, and compares full returns and
  buffer effects under fingerprinted `qemu-i386`/`qemu-arm`. A real i386
  non-vacuity test proves that both a correct recovery and a one-element buffer
  error are distinguished. Rich signatures outside the generated worker's
  integer-scalar/integer-buffer subset retain the explicit `--width-audit`
  fallback; none of these five C++ wrappers use that fallback.
- The one genuine residual i386 O0 defect was `cpp_raii_guard`: a pointer home
  spilled through a casted scratch was not recognized as `arg0`. Later copy
  propagation collapsed “load pointer, store through pointer” into
  `local_1c = 0`. Parameter-home recovery now carries a bounded straight-line
  argument-provenance map through register copies/casts without rewriting
  addresses, and treats later computed stores as parameter reassignment unless
  they are proven to come from a different incoming argument. The emitted body
  now performs `*(int *)arg0 = 0` and passes at the real i386 ABI.

The fresh release-extension matrix executes the five scalar/stack C++ wrappers
at both optimization levels on all four architectures: x86-64 10/10, i386
10/10, AArch64 10/10, and ARMv7 10/10, for 40 passes and zero failures,
non-portable results, incomparable results, timeouts, or lane errors. The exact
Rust AST suite passes 145 tests; the architecture-harness and fixture-harness
Python modules pass in full.

The refreshed full architecture baseline is infrastructure-clean: 1,086 pass,
114 fail, 152 structural, four declared unsupported, and no non-portable,
incomparable, missing, timeout, or lane result. The x86-64 control remains
328/328. An immediate full `--check` replay matches the generated baseline
exactly. Relative to the committed baseline, 26 failures become passes and 32
width-audit-incomparable results become genuine target-ABI passes. Ten C++
wrapper cells improve from fail to pass, and no previously passing C++ cell
regresses.

Eight committed passes become genuine target-ABI failures: i386 O2 `dispatch`
and `tail_dispatch`; ARMv7 and i386 O0/O2 `widen_mul`; i386 O0 `heap_push`; and
i386 O0 `euler_decay_q16`. These are oracle corrections, not changes to their
recovered code. The old LP64 rebuild accidentally supplied register arguments
to no-argument i386 indirect calls, gave ILP32 `unsigned long` a 64-bit host
width in `widen_mul`, and evaluated the latter two recoveries against LP64
layout/semantics. The target worker now records their actual return/buffer
divergence under qemu. They remain red in the regenerated baseline rather than
being hidden by a permissive compatibility classification.

`cpp_virtual_dispatch` remains explicitly structural: its recovered C still
represents two vtable-backed automatic objects as uninitialized pointers and
deterministically crashes on the first x86-64 O0 vector if the quarantine is
removed. That is EPIC 3 aggregate/vptr initialization work, not a hidden green
C++ cell; the structural oracle still requires an indirect call. Mangled C++
ABI entries without recoverable DWARF call signatures remain direct-structural
because safely invoking a constructor/destructor requires a valid `this` object
the harness must not invent. They are nevertheless executed transitively by
the five exported C wrappers that own their objects, arguments, and observable
effects.

**Closure.** The exact C++ matrix remains 40/40 and is reported separately from
the final broad evidence. The full Python suite and all five decompiler lanes
pass; the architecture lane matches the 1,086-pass baseline exactly with zero
infrastructure-result classes.

## D-007 — ARMv7 `getent` mode/extent adjudication

**Observed discrepancy.** angr reports format strings in six stripped ARMv7
functions where Glaurung sees no corresponding printf-family call. Stripping
removed `$a`/`$t` mapping symbols, and a naive reference decode treats Thumb
bytes as ARM instructions.

**Required evidence before code.** Obtain an unstripped twin with mapping symbols
or derive mode/range from `.ARM.exidx`; compare byte-for-byte function extents,
mode transitions, calls, and strings. llvm-objdump's current decode is not an
oracle, and the string pass is not the presumed owner.

**Acceptance.** A trustworthy mode-aware reference adjudicates all six VAs. Only
then assign a discovery, mode-propagation, extent, call, or external-oracle fix.

**Adjudication and closure evidence (2026-08-05).** The retained unstripped twin
`sym_getent_arm-v7` is byte-identical to the original Alpine 3.18 binary
(`96f5bbc4980c0cd24edc5ffc489b1d46ed0e0671040e7b2a098f6eda50523934`),
and its complete `.text` range `0x1080..0x1e0c` is byte-identical to stripped
`strip_getent_arm-v7`
(`191cd1f69d71f9c8eb6bbdf233d9abaf21eaef11c7dd81b46a0478da2529819e`).
The twin's ELF mapping symbols and mode-aware ARM objdump provide the missing
oracle:

- `passwdprint` `0x1320..0x134c`, `servicesprint` `0x13c4..0x13fc`,
  `protocolsprint` `0x14b0..0x14e0`, `groupprint` `0x14e0..0x1514`,
  `networksprint` `0x162c..0x16b8`, and `hostsprint` `0x170e..0x1794` are all
  Thumb code with exact symbol extents; nearby `$d` transitions identify their
  literal pools rather than ARM instructions.
- `passwdprint` directly calls `printf@plt` at `0xd70`; the other five directly
  call the shared Thumb helper `printfmtstrings` at `0x134c`. PC-relative
  literals provide their format/separator addresses. The larger network/host
  functions also retain their expected `inet_ntop`/`strlcpy` calls.
- Fresh stripped-binary replay discovers and decodes all six functions at the
  correct entries and extents and retains those direct call targets. The
  discrepancies are downstream: `passwdprint` leaves its format as numeric
  `0x1ea4`; `networksprint`/`hostsprint` retain numeric string addresses such as
  `0x1ecd`, `0x1ece`, and `0x1ef0`; the three smaller helpers lose PC-relative
  r1--r3 argument provenance before call folding.

D-007 is therefore not a discovery, ARM/Thumb mode, extent, or call-target
defect. The numeric constants belong to EPIC 2's program-level address/string
provenance lane; the lost r1--r3 values belong to the call-argument/reaching-def
lane. This adjudication closes the mode-oracle issue without applying a
fixture-specific string heuristic.

## D-008 — x86 zero-flag operand width

**Observed defect.** `test edi, edi` computes ZF from the untruncated 64-bit
parent while SF uses the signed 32-bit view. Inclusive guard recovery correctly
refuses to merge predicates whose operand identities do not match.

**Required fix.** Compute ZF from the exact encoded operand width at the lifter,
using the same width statement as signed/unsigned comparisons. Do not relax
`bool_guard` until both predicates are semantically identical.

**Canaries.** Exact `test`/logic instruction encodings for 8/16/32/64-bit
register and memory operands; high-parent-bit negative controls; `jle`/`jg`
behavior; `01_conditional_polarity:gcc:O2:sc_mixed`; and the full 328/328 x86
control lane.

**Lane note.** The existing `agent/x86-flags` worktree currently implements
BSR/BSF semantics and changes `shift_until_zero`; it does not implement this ZF
width fix and must not be mistaken for D-008 evidence.

**Current evidence (2026-08-06, branch `agent/defect-register`).** `TEST` was
the sole x86 flag producer bypassing the shared width boundary. It materialized
`lhs & rhs` in a temporary, sign-extended that temporary from the encoded width
for SF, but compared the raw temporary with zero for ZF. Once register-view
canonicalization exposed a 64-bit parent, ZF and SF therefore described
different values.

The `TEST` lifter now sends its one materialized result through the existing
`zero_sign_flags` helper. Narrow byte, word, and dword forms get explicit
zero- and sign-extended views from the same encoded width; the qword form keeps
the unmodified result. The bespoke raw-result ZF helper is removed. No
consumer, `bool_guard`, comparison-merging, or fixture exception was changed.

- RED/GREEN coverage pins register and memory encodings at 8, 16, 32, and 64
  bits. It explicitly distinguishes the high-parent-bit behavior of
  `test edi,edi` from `test rdi,rdi` and requires both ZF and SF to consume the
  corresponding width view.
- All 114 `ir::lift_x86::tests` pass, including the existing `jle` and `jg`
  composite-predicate canaries.
- A fresh release extension passes all 12 pinned GCC O2
  `01_conditional_polarity` verdicts, including `sc_mixed`.
- The complete x86-64 architecture control remains 328/328, with 38 explicit
  structural verdicts and no failure, incomparable, missing, timeout, or lane
  result.

**Closure.** The final full Python and five-lane decompiler gates pass with the
complete register applied. The x86-64 architecture control remains 328/328 and
the complete architecture baseline matches exactly.

## Overall completion audit

The register is complete only when every D-001 through D-008 entry is **CLOSED**,
all named fixtures/oracles have current evidence, the full Rust/Python/lint/type
gates pass, the full decompiler gate has a final successful exit, owned commits
are integrated, and no compatibility API or documentation still describes the
fixed defect as open.

### Final defect-validation ledger — 2026-08-06

- `uv run pytest python/tests/ -q --tb=short` reached 100% and exited 0. The
  first replay exposed one environment-sensitive test: the purportedly offline
  `test_explain_runs_offline_pipeline_on_hello_world` inherited provider keys
  from the repository `.env` and invoked an LLM. The immutable base reproduced
  the same failure. Its subprocess now explicitly supplies empty provider
  credentials, the exact RED test passes, its complete module passes with seven
  passes and one fixture-dependent skip, and the definitive full replay is
  green.
- `scripts/decbench-local-gate.sh` exited 0 with the exact final line
  `HEAVY GATE: passed (all five lanes ran)`. Rust, the 31-test x86-64 fixture
  and structural matrix, the architecture round trip, both executable behavior
  corpora, and the metric ratchet all report `ok`.
- The architecture lane matches its baseline exactly: x86-64 328/328, i386
  251/272, AArch64 279/328, and ARMv7 228/272; total 1,086 pass, 114 fail, 152
  structural, four declared unsupported, and zero non-portable, incomparable,
  missing, no-case, timeout, or lane-error result.
- The metric lane reports `FULL MATRIX: no per-cell regressions across 56 of 56
  cells`. No metric waiver or missing-lane allowance was used.
- `cargo fmt --check`, `git diff --check`, JSON parsing for both ratchets, and
  shell syntax validation pass. Scoped Ruff checks for every changed Python
  harness/test module pass.

### Repository-wide quality debt

The defect work adds no repository-wide quality regression, but the strict
overall completion audit is **not green** because the base repository already
fails its global Python gates:

| Gate | Base `fcca960b` | Defect branch | Verdict |
|---|---:|---:|---|
| `uvx ruff check python/` | 3,510 errors | 3,509 errors | red; one error removed |
| `uvx ruff format --check python/` | 309 files | 308 files | red; one file repaired |
| `uvx ty check python/` | 2,041 diagnostics | 2,041 diagnostics | red; exact parity |

Mass-formatting or mechanically rewriting hundreds of unrelated files is not a
safe defect-register change. These failures therefore remain explicit release
debt rather than being called green or hidden behind scoped checks. They do not
reopen D-001 through D-008, whose implementation, focused proof, broad behavior,
and metric evidence are complete.

### Integration disposition

The audited base `fcca960bd7490c452a541f1034d13f2dd4e98eda` remained the remote
`master` tip after the final gates. The complete defect sequence was therefore
integrated with a normal fast-forward push: no merge repair, force, or history
rewrite was used. At handoff, `origin/agent/defect-register` and
`origin/master` resolve to the same final ledger object. The original local
`master` worktree has overlapping uncommitted work and was deliberately left
untouched on its existing local ref.

## Post-register architecture audit — 2026-08-06

This section restores the findings that were present only in the untracked
`wt-globals` audit. It does not reopen D-001 through D-008; it corrects the scope
and evidence around the next work. Where a figure below differs from an older
entry, this section is authoritative for the current six-lane harness. The full
component design, file-size decomposition, phases, acceptance criteria, and stop
conditions are in
[`decompiler-rearchitecture-2026-08-06.md`](decompiler-rearchitecture-2026-08-06.md).

### ILP32 source support is not ARM validation

The harness classification “unsupported on a 32-bit source target” describes a
source-language/toolchain limitation such as `__int128`; it does not demonstrate
an ARM architecture failure. Conversely, the old ARM32 lane compiled Thumb only,
so its verdicts did not validate A32 instruction semantics. These two dimensions
must remain separate in reports and baselines.

The missing A32 coverage now exists as `armv7_a32`, built with `-marm` and run
with `qemu-arm`. Its initial baseline is 112/272 (41.2%), with 160 failures, 38
structural-only results, and two declared unsupported source cases. The existing
Thumb lane is 238/272 after the CFA widening. Neither may stand in for the other.

### The control compiler was confounded with the architecture

The pinned x86-64 GCC 11.4 control remains 328/328. A distinct host-GCC-15
x86-64 lane is now 323/328. All five GCC-15 failures had previously appeared on
the non-control architecture lanes:

1. `02_integer_widths:O2:reconstruct_64`;
2. `03_loop_shapes:O2:for_sum`;
3. `03_loop_shapes:O2:loop_continue`;
4. `11_call_shapes:O2:call_into_spill`; and
5. `14_flag_effects:O2:shift_until_zero`.

These are compiler-shape failures until a narrower owner is proved. They are not
valid evidence of an architecture gap merely because pinned GCC 11 does not emit
the same shapes.

### DecBench ARM metric soundness

Production `byte_match` does not grant an unconditional 1.0 when two decoded
instruction lists are empty: raw extracted function bytes remain the fallback.
The real metric defect was symbol-declared ARM mode/range handling. A Thumb
function may carry its T-bit in the declared address; object extraction needs the
masked address while Capstone needs the T-bit to select Thumb rather than A32.

The correction, cache-version bump, and nine regressions are DecBench commit
`cc680f8`, proposed upstream as Noelo-Lab/decbench PR #61. It covers object
extraction, T-bit preservation, A32/Thumb mode selection, and non-ARM controls.
Published ARM figures remain due for regeneration after the correction, but the
broader “empty ARM means a free perfect score” rationale is withdrawn.

### Evaluation-tree reproducibility

The current DecBench corpus now has a complete persistent source rebuild at
`/nas4/data/binary-analysis/decbench-holdout-source-rebuild-2026-08-06`:
41 projects, 122/122 declared project/optimization cells, 880 linked binaries,
and 11,885 preprocessed source files. This is a distinct evaluation universe;
its binaries are not relabeled as the old 250-function holdout.

The rebuild exposed two driver defects: PE executables were reported as failed
because only ELF linked images counted, and the driver ignored per-project
optimization declarations. The tested correction and required image/dependency
updates are clean DecBench commit `a3583d7`, proposed upstream as PR #62.

The exact historical 250-entry manifest is absent. The first fresh direct score
run therefore uses the 239 unique keys with a published Codex sample and is
labeled `published-codex-239`. It is a falsifiable current proxy, not a claimed
reproduction of the historical holdout. Its canonical finalization realizes 222
exact rows and no extras: GED is finite for 218 rows (mean 22.9312, median 10),
type match for 210 (mean 0.26185, median 0.11111), and byte match for all 222
(mean 0.13425, median 0). Seventeen manifest keys are absent because of missing
DWARF/source filters or zero matched decompilations. The new type mean is
encouraging but is not a like-for-like clearance of the historical Ghidra 0.231
bar; the binaries, compilers, and realized key set differ.

The direct GED result is still above the historical Ghidra 20.43 bar. Five rows
contribute 1,003 of 4,999 total GED; removing only those five lowers the mean to
18.76. The worst is generated parser `yyparse` at 337, followed by large
buffer/sort/parser functions. Work should therefore target total control-region
recovery and size-stratified evaluation, not add a fixture-specific loop printer
rule.

### `linkedlist:clang:O0` is an emission regression

The exact historical Glaurung base `b83a066` and pre-follow-through `master` both
score GED 0.0 on the same input, but byte match falls 0.47 to 0.10. The old
register's “structurally closer” explanation is withdrawn: GED observes CFG
topology, which was already perfect at the base, and says nothing about
instruction-level shape. A corrected `git bisect run` identifies
`b2003b556cea929b333f4699c26d207700626482` as the first bad commit; its scope
included the expanded O0 parameter-home coalescer and cross-architecture frame
changes.

At that bad state, output invented `stack_top[8]`, forcing stack-protector/frame
code; `list_sum` fell from 0.3793 to 0.1190; and `list_find` did not compile,
reducing its metric score from 0.5667 to zero. The direct type/storage slices in
`199af22`, `9a6f627`, and `1fc76ab` remove the false array, retain `node *` through
the promoted result slot, keep the slot distinct from `node::next`, and emit a
valid lvalue. On the rebuilt extension, `list_sum` is 0.1935 and `list_find` is
0.4194, so the official cell recovers to byte match 0.31 (GED 0.0, type match
1.0). The residual gap to 0.47 remains O0 parameter-home/instruction-shape debt,
not a metric waiver.

### Direct type-match correction

The DWARF signature path previously rejected every parameter when any sibling
used an unavailable typedef. Commit `199af22` changes this to independent
renderability: concrete siblings retain their exact source contracts, while
only an opaque slot falls back to an ABI-safe type. It also accepts multi-level
and `void *` parameters and normalizes repeated qualifiers. Fresh real-binary
signatures now include `gyroInitFilterNotch1(uint16_t, uint16_t)`,
`compare_files(char **)`, and three retained source-level pointer categories in
`pkg_array_match_patterns`. Fully representing its opaque function-pointer
parameter still requires EPIC 1's structured declarator/type environment.

### Current strict AArch64-only set: 5, not 43

The old 43-function count was a verdict-only snapshot and is stale. Relative to
the current pinned x86-64, i386, and Thumb lanes, the strict AArch64-only set is:

- `03_loop_shapes:O2:{for_sum,loop_continue,mutate_reverse}`;
- `05_struct_arrays:O0:process`;
- `07_packet_parser:O2:validate_header`.

The post-spill call-result ownership fix closes 11 strict AArch64-only failures:
`fib`, O0 `validate_header`, all three indirect-dispatch functions, two O0 call
shapes, both O0 hash-table functions, and both O0 disjoint-set functions. A
consumed call destination now changes role with its post-spill consumers instead
of leaving `call -> x0` followed by `store <- scr_x0` as two unrelated values.
The complete six-architecture ratchet moves from 1,531 passes / 269 failures to
1,542 / 258, with no regression or reclassification.

The next AArch64 O2 call-flow slice closes `call_chain_in_loop` and
`call_into_spill` at argument reconstruction. AAPCS64 now retains the proven
loop-carried x0 input for a zero-setup call. For the eight-register tail-call
shape, a recovered higher argument slot proves the contiguous prefix; x1 setup
that feeds x3/x5/x7 stays statement-rooted, and the immediately prior call result
gets a distinct value used as x0 and in every derived argument. The complete
ratchet moves again to 1,544 passes / 256 failures, with exactly these two
fail-to-pass changes and no reclassification.

The rotated-loop value-role slice then closes
`12_loop_rotation:aarch64:O2:{factorial_while,nested_rotated}`. Their 64-bit
loop results occupied x0 after 32-bit entry parameters had used the same
storage. Lifting and structuring kept the wide arithmetic, but flat role naming
renamed both values `arg0`, forcing a 32-bit truncation on every iteration. The
shared storage-reuse pass now splits that lifetime only when the recovered
prototype proves a direct result, a slot-zero/result-register alias, exact
result definitions, and unequal scalar widths. The complete ratchet moves to
1,546 passes / 254 failures, with exactly these two changes.

The DWARF array-extent slice then closes four AArch64 O0 frame failures:
`graph_bfs`, `graph_dfs`, `dijkstra_dense`, and `kmp_search`. Their array DIEs
carry element types and subrange bounds but no direct byte size. Following only
the element type downgraded each array to a scalar, so a constant initializer
and indexed accesses became unrelated C objects. Array extents now multiply
the recursively recovered element size by every proven subrange count, with
language-aware lower bounds plus cycle and overflow guards. The complete
ratchet moves to 1,550 passes / 250 failures, with exactly these four changes.

The remaining root causes still split across architecture layers. `for_sum`
needs AArch64 SIMD horizontal-reduction semantics; the other cells retain
control-flow, aggregate-shape, or packet-parser value-role defects. The set is
therefore triage evidence, not one “AArch64 gap.”

### Rank-ordered next work

1. **P0 — sound definitions and value roles (EPIC 5).** Replace bare-name and
   last-writer queries with one reaching-definitions oracle used by call-result,
   phi, frame, and return recovery. The post-spill call-result collision slice is
   complete, as are the adjacent AArch64 call-flow and rotated-loop value-role
   slices; next acceptance is the linked-list false frame without
   architecture-ratchet regressions.
2. **P0 — program environment and call contracts (EPIC 1).** Persist one
   program-level symbol/type environment and attach canonical prototypes to every
   direct and indirect call site. Acceptance: pointer-depth type canaries and
   indirect-call declarations improve with complete structured variables.
3. **P1 — storage-backed aggregate recovery (EPIC 3).** Make stack/global objects
   first-class, merge CFA/current-SP evidence into one storage identity, and derive
   arrays/struct extents from access paths. Acceptance: no invented `stack_top` in
   linked-list output and stable ARM constructor/destructor aggregate identity.
4. **P1 — architecture-parametric semantics (EPIC 4).** Move calling-convention,
   register-bank, stack-coordinate, and SIMD semantics behind machine-model traits;
   keep A32 and Thumb as distinct test targets. Acceptance: implement AArch64
   `addv`-class reductions and increase A32 from its measured baseline without
   architecture-name gates in shared IR passes.
5. **P2 — symbolic constant operands (EPIC 2).** Resolve data/code addresses,
   literals, and table bases through the program environment instead of preserving
   opaque integers. Acceptance: address-bearing operands retain symbol, section,
   width, and relocation provenance through lifting and C emission.
6. **P2 — direct metric campaign.** After the preceding typed/storage slices,
   rerun the retained 239-key proxy and then freeze a new 250-function manifest.
   Require complete coverage and per-function GED/type-match deltas; do not accept
   generated-text improvement without behavioral and compiler controls.
