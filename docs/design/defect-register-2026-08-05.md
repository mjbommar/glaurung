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
| D-001 | Phi-copy widths collapse distinct bare-name definitions | FIXED / GATES PENDING | `agent/defect-register` |
| D-002 | Optimized large-function extents are wrong | CLOSED | adjudicated on `agent/defect-register` |
| D-003 | AAPCS outgoing stack arguments stop at repeated slots | FIXED / GATES PENDING | `agent/defect-register` |
| D-004 | Large ARM table dispatches do not structure | FIXED / GATES PENDING | `agent/defect-register` |
| D-005 | Wrapped 32-bit array indices render as huge unsigned values | OPEN | unowned |
| D-006 | C++ recovery lags across i386, AArch64, and ARMv7 | OPEN | unowned |
| D-007 | Six ARMv7 `getent` string/call discrepancies lack a trustworthy mode oracle | CLOSED | adjudicated on `agent/defect-register` |
| D-008 | x86 ZF is computed from an untruncated parent register | OPEN | unowned; `agent/x86-flags` is separate BSR/BSF work |

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
- The full five-lane local gate ran. Rust, the x86-64 structural/behavioral
  matrix, all cross-architecture round trips, and both executable DecBench
  corpora passed. The metric ratchet failed on three committed-baseline deltas:
  `linkedlist:{clang,gcc}:O2` GED 0 -> 2.5 and `matrix:clang:O2` GED 21 -> 24.
- Those three failures are not branch regressions. A detached worktree at the
  exact base object `fcca960bd7490c452a541f1034d13f2dd4e98eda` reproduced all
  three current scores, and each generated C artifact was byte-identical to the
  branch artifact (SHA-256 `35f453e0...`, `210cb1b8...`, and `7a2e5da9...`).
  The committed metric baseline is therefore already stale relative to its own
  base commit and current evaluator; it must not be rewritten without first
  explaining that drift.

**Remaining before closure.** Explain and repair or deliberately rebaseline the
pre-existing metric-ratchet drift; replay the historical 4,033-attempt corpus if
recovered; commit and integrate the owned path only after that gate contract is
trustworthy.

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

**Remaining before closure.** Run the final full Rust/Python/decompiler gate
after the other register fixes and reconcile the already-recorded metric-ratchet
drift. Mixed VFP/core calls which themselves spill remain deliberately
fail-closed until the call layout owns explicit stack locations.

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

**Remaining before closure.** Run the final full Rust/Python/decompiler gate and
the broad ARM controls after the other register fixes, then reconcile the
already-recorded metric-ratchet drift.

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

## Overall completion audit

The register is complete only when every D-001 through D-008 entry is **CLOSED**,
all named fixtures/oracles have current evidence, the full Rust/Python/lint/type
gates pass, the full decompiler gate has a final successful exit, owned commits
are integrated, and no compatibility API or documentation still describes the
fixed defect as open.
