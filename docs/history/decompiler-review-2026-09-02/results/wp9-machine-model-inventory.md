# WP9 machine-model ownership inventory

Date: 2026-09-03

This inventory is the prerequisite for migrating machine facts behind one
queried contract. It records the live implementation, not the intended final
architecture. In particular, `src/target/` already owns target identity; WP9
must extend that boundary rather than introduce a competing `MachineModel` in
`src/ir/machine/`.

## Current support boundary

| Concern | Current owner | Covered targets | Important gap |
|---|---|---|---|
| Target identity, pointer/address width, byte order, format, OS ABI, instruction mode | `src/target/spec.rs` | x86-32, x86-64, ARM32 A32/Thumb, AArch64; unsupported identity for MIPS, PPC, and RISC-V | Consumers do not all receive or query `TargetSpec` |
| Special-register roles | `src/target/registers.rs` | all four lifted targets | Only stack, frame, link, and program-counter roles |
| Calling-convention identity | `src/target/abi.rs` | cdecl32, SysV AMD64, Win64, AAPCS32 soft/hard-float, AAPCS64 | Identity is centralized; most storage/effect facts are not |
| Register views and overlap | `src/target/register_views.rs`, `src/ir/regview.rs` | ARM32 core and complete VFP/NEON storage hierarchy; x86-64 and AArch64 compatibility views | No target-owned x86-32/x86-64/AArch64 profile; partial ARM VFP definitions still need read-modify-write lowering |
| ABI argument, result, clobber, and width facts | `src/ir/abi.rs` and `src/ir/abi/` | all six conventions above | One large IR module rather than target-owned queried facts |
| Call argument reconstruction | `src/ir/call_args.rs` and `src/ir/call_args/` | all six conventions, with target-specific branches | Consumers still switch directly on `CallConv` |
| Stack/frame recovery | `src/ir/stack_locals.rs`, `src/ir/*_prologue.rs`, `src/python_bindings/ir/pipeline.rs` | x86, ARM32, AArch64 families | Frame bases, word sizes, saved registers, and cleanup rules are repeated |
| Flag semantics | `src/ir/lift_x86/flags.rs`, `src/ir/lift_arm32/flags.rs`, `src/ir/lift_arm64/flags.rs` | per lifter | Correctly target-specific implementations, but no shared capability query |
| Instruction semantics | `src/ir/lift_x86.rs`, `src/ir/lift_arm32.rs`, `src/ir/lift_arm64.rs` and submodules | x86/x86-64, ARM32, AArch64 | No standing per-target decoded-versus-lifted capability contract |
| Unknown/effect coverage | `src/ir/effect_census.rs`, `src/ir/effect_census_tests.rs`, two reviewed exemption manifests, lane baseline, x86 `SILENT_REGISTER_WRITERS` test | real-binary denominators for i386, x86-64, ARM32 A32/Thumb, and AArch64 | census is not yet wired into a named required repository gate; reviewed opaque semantics and 13 silent-writer mnemonic classes remain |

`src/target/conformance_tests.rs` independently walks the complete
`Arch x Format x Endianness x arm_hard_float` product. It proves target
classification and fail-closed unsupported identities; it does **not** prove
that every downstream decompiler pass is portable to every row.

## Duplication and migration pressure

The live source has 56 files under `src/ir/` and
`src/python_bindings/ir/` that directly mention `CallConv`, `regview::Arch`, or
the four lifted `Arch` variants. The count is a discovery aid rather than a
quality metric: some switches belong in target-specific lifters. The risky
copies are shared passes deciding any of these facts themselves:

- machine word and pointer width;
- aliases and partial-register write behavior;
- argument and result storage classes;
- caller/callee-saved register sets;
- frame, stack, link, and program-counter roles;
- instruction alignment and PC-relative bias.

The first migration should be ARM32 register views because it is the only
lifted 32-bit register target without an explicit view model and because VFP
single/double overlap makes an incomplete model fail visibly. The rejected
standalone i386 SSA-parent experiment remains evidence that x86-32 cannot be
silently mapped onto the x86-64 identity rules.

## Contract to extend

Keep `TargetSpec` as the immutable entry point. Add narrow query types under
`src/target/` only when a consumer is migrated:

1. Extend register storage with an architecture-qualified view query covering
   parent, offset, width, bank, zero-extension, and partial-definition masks.
2. Move ABI storage queries behind a target-owned contract while retaining
   `crate::ir::abi` compatibility forwards during incremental migration.
3. Expose frame and special-register roles from that same target contract.
4. Keep opcode semantics in each lifter; add only a capability/result contract
   shared by the census.
5. Default an unmigrated or unknown query to an explicit unsupported/unknown
   result. Never select x86-64 or SysV as a generic fallback.

This is deliberately not a big-bang module move. Existing shared-pass behavior
must remain byte-identical after each accepted fact-class migration.

## First implementation slice: ARM32 GP and VFP views

Status: implemented locally for core aliases and scalar `s`/`d` pairing; MIR
effect completeness is the first consumer. An isolated full Rust gate passes,
and the isolated slice and untouched control produce identical verdicts over
all 410 ARMv7 O0/O2 lanes. Promotion remains blocked by the repository-wide
Python gate. The follow-up increment now also models `q0..q15` as the widest
NEON storage parents. The release-built 410-lane ARMv7 O0/O2 sweep remains
verdict-identical to the untouched `d14748cf` control (184 historical baseline
regressions and 5 improvements in both). Production SSA/type consumers remain
outside the original slice. The follow-up SSA migration now queries
`TargetSpec::complete_register_write_parent` for ARM32 definitions and removes
SSA's duplicate core-alias table; partial VFP definitions remain deliberately
unmerged pending correct read-modify-write lowering.

### Production files

- `src/target/register_views.rs` now owns the ARM32 query type without adding a
  second target identity enum. Core aliases remain independent; `s` and `d`
  spellings are bit windows within their canonical `q` parent.
- `src/ir/regview.rs` remains the x86-64/AArch64 compatibility implementation
  while existing callers migrate.
- `src/ir/mir/builder.rs` now queries the target-owned ARM32 view before its
  compatibility path; partial VFP writes invalidate register-effect
  completeness conservatively.
- `src/ir/ssa.rs` now queries the target-owned complete-write contract for
  ARM32 definition identity instead of maintaining its own core-alias match.
- Only after the query is proven, migrate ARM-specific name/overlap branches in
  `src/ir/types_recover/float_bank.rs` and call-result handling.

### Required RED tests

- `r0`/`r0` is one complete 32-bit GP storage identity.
- `s0` and `s1` are the low and high 32-bit views of `d0`; a single `s0` write
  leaves `d0` partially defined, while `s0+s1` defines it completely.
- `d0` is not an alias of `r0:r1`; core and VFP banks stay distinct.
- AAPCS soft-float and hard-float select the same architectural views but
  different argument/result allocation.
- An ARM32 view queried under x86-64 or AArch64 returns unsupported rather than
  matching by spelling.

### Acceptance evidence

- focused target/register-view unit tests;
- existing `src/target/conformance_tests.rs` cross-product remains green;
- `python/tests/test_decompiler_arm32_semantics.py` and
  `python/tests/test_decompiler_arm_frame_spills.py` remain green;
- byte-identical ARM32 fixture sweep, except for a separately reviewed and
  execution-proved improvement;
- no increase in residual `Op::Unknown`, opaque intrinsic, or silent-writer
  totals for any measured architecture.

## Capability-census follow-up

Build on `src/ir/effect_census.rs`; do not create a separate census with a
different definition of unknown effects. Add i386 to the committed corpus,
emit lane keys containing target/mode/compiler/optimization, and introduce one
reviewed exemption manifest. Each entry must contain target, mnemonic or
encoding family, observed count, reason, semantic risk, owner, and expiry or
removal condition. The required gate must fail when:

- a decoded mnemonic becomes `Op::Unknown` or an unreviewed opaque intrinsic;
- a known exact mnemonic re-enters `SILENT_REGISTER_WRITERS`;
- an exemption no longer fires or its observed count increases;
- a supported target/mode has no fixture denominator.

The census establishes what is missing. It is not evidence that an exempted
instruction is semantically supported.

### Implemented census foundation

The real-binary corpus now covers every lifted target, adding an existing
committed i386 MinGW PE to the existing x86-64, ARMv7, and AArch64 samples. The enforced
denominator test fails if any target has no file, lifted function, or
instruction. `tests/decompiler_fixtures/effect_census_exemptions.json` is the
single reviewed manifest for post-lift opaque effects. Its test rejects unknown
targets, missing review fields, overlapping patterns, stale zero-hit entries,
observed-count increases, and any opaque mnemonic with no exemption.

The independent decoded-to-LLIR gate walks the exact accepted block ranges,
decodes them separately from the lifter, and correlates by source address. It
proves that no decoded instruction disappears and requires every instruction
which produces only maximally opaque LLIR to match the reviewed
`tests/decompiler_fixtures/decoded_lift_exemptions.json` manifest. This keeps
the raw machine mnemonics visible even when lowering normalizes several of
them into one intrinsic family.

Current measured scope is 10 binaries, 432 functions, and 53,488 instructions.
The 236 opaque effects are all explicit work items rather than silent coverage:
194 i386 x87-family operations, 16 x86-64 trap/hint operations, and 26 ARM
system-call or predicated-control effects. AArch64 has a non-empty denominator
and zero opaque effects. Raw decoded denominators are 6,236 i386, 8,394
x86-64, 812 AArch64, and 228 ARMv7 instructions; their opaque totals reconcile
exactly with the post-lift 194/16/0/26 counts. Generic-intrinsic growth is now
ratcheted per lane alongside opaque effects: the committed baseline caps the
combined total while retaining a strict zero allowance for `Op::Unknown`.
Silent-register-writer coverage is also bounded by an exact per-mnemonic
ceiling. Sixteen-bit `bsr`/`bsf` was removed from that list by explicit
lowering which snapshots the 16-bit source, performs the scan in a 32-bit
temporary, and merges the 16-bit result back into the destination parent. A
numeric regression proves `bsr cx, ax` maps source `0x0800` to result `0x000b`
while preserving the upper destination bits. This removes all four observed
`bsr` instances; 23 reviewed mnemonic classes remain.

Focused validation for this increment passed 196 x86 lifter tests, all 24
register-view integration tests, and the eight active capability-census tests
(with the intentionally slow reporter ignored). The increment was then applied
without the shared worktree's unrelated changes to the existing isolated
`d14748cf` WP9 overlay. `cargo test --features python-ext` completed with exit
code zero: the library target ran 3,074 tests (3,071 passed and 3 ignored), and
every integration and doc-test target passed.

The next ratchet increment models `cpuid`, `rdtsc`, `rdtscp`, and `xgetbv` as
environment-dependent intrinsics rather than fabricated constants. Their
architectural inputs and every 32-bit result are explicit; x86-64 results are
zero-extended into their canonical parents, while i386 writes remain complete
32-bit definitions. AST lowering was extended at the same time because its
single-statement compatibility path retained only output zero: query
intrinsics now produce one honest unknown-valued assignment for every declared
output, so later reads do not become invented live-ins. RED tests reproduced
both the original `cpuid` `Op::Unknown` and the AST's one-of-four output loss.

This removes 12 observed silent writes (six `cpuid`, two each of `rdtsc`,
`rdtscp`, and `xgetbv`) and reduces the reviewed list from 23 to 19 mnemonic
classes without increasing any per-lane generic-intrinsic ceiling. Focused
validation passed both i386/x86-64 query contracts, the AST multi-output
contract, all 198 x86 lifter tests, the silent-writer corpus ratchet, and all
eight active capability-census tests. The post-cleanup isolated `d14748cf` WP9
overlay passed `cargo test --features python-ext`: 3,074 of 3,077 library tests
passed with 3 ignored, followed by every integration and doc-test target.

The following VEX increment adds exact 128-bit `vpxor` lowering instead of
routing its three-operand form through the two-operand SSE model. Register and
memory forms read both explicit sources into four dword lanes, self-XOR of the
two sources produces a proven zero, and the existing XMM-view synchronizer
redefines the whole destination. YMM forms remain an explicit decline because
the LLIR cannot represent their 256-bit storage. RED first reproduced the raw
`Op::Unknown`; focused tests then covered distinct register sources, four-lane
memory input, source self-zeroing, whole-view consistency, and the standing
silent-writer/capability ratchets. This removes four observed `vpxor` silent
writes and leaves 18 mnemonic classes. The isolated `d14748cf` WP9 overlay
passed the full Rust gate with 3,076 of 3,079 library tests passing and 3
ignored, followed by every integration and doc-test target.

A form-level census now pins the exact remaining SIMD encodings rather than
assuming their widths from mnemonics: 58 YMM loads and 34 YMM stores for
`vmovdqu`, 2 YMM `vpand`, 2 YMM `vpbroadcastb`, 12 YMM `vpcmpeqb`, and 8 YMM
`vpmovmskb`. Any new representable 128-bit form changes that map and fails the
test instead of inheriting a width exemption.

The same increment lifts `pushfq` and `popfq`. Because LLIR represents seven
status bits rather than the entire flags word, `pushfq` emits an explicitly
unknown packed-word intrinsic which consumes CF/PF/AF/ZF/SF/DF/OF, then
performs the exact stack decrement and store; it does not fabricate the other
architectural bits. `popfq` loads the word, extracts each represented bit at
its architectural position, and increments the stack pointer. RED reproduced
the original `pushfq` `Op::Unknown`; the standing ratchet then required both
stale allowances to be removed. This eliminates four observed silent writes
and leaves 16 mnemonic classes. Focused validation passed all 202 x86 tests,
the form census, silent-writer ratchet, and eight active capability tests. The
isolated `d14748cf` WP9 overlay passed the full Rust gate with 3,078 of 3,081
library tests passing and 3 ignored, followed by every integration and doc-test
target.

The next bounded SIMD increment models the exact 256-bit `vmovdqu` forms as
eight independent 32-bit transport lanes. A move does not interpret its bits,
so this is lossless for YMM register copies and 32-byte loads/stores without
claiming general AVX semantics or a first-class 256-bit LLIR value. Encoding-
level RED tests cover register, memory-load, and memory-store forms and require
all eight lane names and offsets. The real-binary ratchets independently show
that all 58 observed YMM loads and 34 observed YMM stores left the unmodelled
form census, while `vmovdqu` left the silent-register-writer list. Fifteen
reviewed silent-writer mnemonic classes remain. Focused validation passed all
204 x86 lifter tests in the shared tree. The exact increment was then applied
to the isolated `d14748cf` WP9 overlay, where all 203 x86 tests at that pinned
base passed. Its complete `cargo test --features python-ext` gate passed 3,080
library tests with 0 failures and 3 ignored, followed by every integration and
doc-test target.

The same exact-lane approach now covers the remaining representable measured
YMM operations `vpand` and `vpbroadcastb`. Three-operand `vpand` preserves both
sources through eight independent dword ANDs, including an eight-load memory
form. `vpbroadcastb` reads or extracts exactly one byte, widens and replicates
it into one dword, then defines all eight destination lanes. Four encoding-
level RED tests cover register and memory forms. The corpus ratchets removed
both mnemonic classes and all four observed forms, leaving only `vpcmpeqb` and
`vpmovmskb` in the watched YMM form map and 13 silent-writer classes overall.
The live shared tree passed all 208 x86 lifter tests. The isolated `d14748cf`
overlay passed all 207 tests at its pinned base and the complete Rust gate:
3,084 library tests passed, 3 were ignored, and every integration and doc-test
target passed.

The decoded-to-LLIR addition was then copied byte-for-byte into the isolated
`d14748cf` overlay. `cargo test --features python-ext` passed 3,069 library
tests with 0 failures and 3 ignored tests, every integration target, and doc
tests.

The corpus table records compiler and optimisation provenance on every
sample. Values come from the committed metadata sidecars and their recorded
output paths: absent cross-build optimisation is explicitly `unknown`, while
assembler output is `not-applicable`. The enforcing test rejects missing
values, duplicate paths, absent binaries, and an unreviewed change from the 10
known samples. Per-function instruction mode is derived from the discovered
function flags, splitting the ARM artifact into distinct A32 and Thumb lanes.
`tests/decompiler_fixtures/effect_census_lane_baseline.json` records all 10
resulting target/mode/compiler/optimisation keys. Each row has minimum file,
function, and decoded-instruction denominators plus a maximum opaque count, so
coverage loss and precision regression both fail closed while improvements do
not require accepting a new baseline. The exact-file isolated `d14748cf`
overlay passed the complete Rust gate with 3,074 library tests passed, 0
failed, and 3 ignored, followed by every integration target and doc test.

An exact-file isolated overlay at `d14748cf` passed the complete
`cargo test --features python-ext` gate: 3,068 library tests passed with 0
failures and 3 ignored tests, and every integration target and doc test also
passed. This verifies the combined WP9 register-view, SSA-query, and census
slice independently of concurrent source changes in the shared worktree.
