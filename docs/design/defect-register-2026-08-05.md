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
| D-002 | Optimized large-function extents are wrong | OPEN | unowned |
| D-003 | AAPCS outgoing stack arguments stop at repeated slots | OPEN | unowned |
| D-004 | Large ARM table dispatches do not structure | OPEN | unowned |
| D-005 | Wrapped 32-bit array indices render as huge unsigned values | OPEN | unowned |
| D-006 | C++ recovery lags across i386, AArch64, and ARMv7 | OPEN | unowned |
| D-007 | Six ARMv7 `getent` string/call discrepancies lack a trustworthy mode oracle | ADJUDICATE | unowned |
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

**Current evidence (2026-08-06, branch `agent/defect-register`).**

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
