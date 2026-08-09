# Glaurung DecBench gap-analysis diary — 2026-08-08

**Status:** original pinned evidence complete; fresh baseline/current replay complete

**Companion plan:** [decbench-remediation-roadmap-2026-08-08.md](decbench-remediation-roadmap-2026-08-08.md)

**Glaurung:** `c1cfdc97fdf51a5028aff5f7507033d70d16ad42`

**Current replay candidate:** `9c25fcb860fb433b59bb24b3f880e8ae3a38a972`

**DecBench main:** `0a4e85bc8a0a1ff5246f6299697f59d30634fcaf`

**DecBench ARM correction:** PR [Noelo-Lab/decbench#61](https://github.com/Noelo-Lab/decbench/pull/61), commit `cc680f886bbe5cf6791a86b146bbeb5dc0547134`
**Dataset:** `0a2d996de2e85452c457af3cc52d8c4b0d376944`

This is an evidence log, not a claim that Glaurung is already present on the
public scoreboard. PR [Noelo-Lab/decbench#56](https://github.com/Noelo-Lab/decbench/pull/56)
is the submission and remains maintainer-controlled. The ranks below are
projections obtained by adding the fresh Glaurung results to the pinned official
function-results snapshot. PR #61 must also be merged and the full board
recomputed before ARM `byte_match` comparisons are final.

## Review questions

The review was organized around five requested epics and three engineering goals:

1. a program-level symbol and type environment;
2. contextual symbolization of constant operands, not only calls;
3. aggregate and structure recovery;
4. an architecture-parametric machine model, using ARM32 as the stress case;
5. a sound definedness and reaching-definitions oracle;
6. better ownership, composition, and DRY code;
7. fewer mixed-responsibility thousand-line files; and
8. better performance, safety, and reliability.

## 15:10–15:35 — repository and artifact boundary

The primary checkout was dirty and behind the current remote. All review work was
therefore performed in the isolated worktree
`/tmp/glaurung-decbench-c1cfdc9`, branched as
`codex/decbench-gap-roadmap-20260808` from current `origin/master`.

The fresh external run covered all 224 binaries and 250 selected functions. Its
raw package is `glaurung-c1cfdc97-results.zip`, SHA-256
`a2c5d731b532373315e16bbcd0458d4a5a2612780550120466569f7b46a24d38`.
All invocations returned successfully and the package was deterministic.

The raw execution profile was:

| Measurement | Result |
|---|---:|
| wall time, 12 workers | 64.04 s |
| per-binary mean | 3.37 s |
| per-binary median | 2.82 s |
| per-binary p95 | 5.10 s |
| slowest binary | 18.77 s |
| failed invocations | 0 / 224 |
| returned functions | 250 / 250 |

This is an end-to-end CLI profile, not a microbenchmark. It includes process
startup and repeated program setup, which is precisely why a reusable program
session is a performance priority.

## 15:35–16:05 — metric soundness correction

DecBench main still decoded ARM functions without honoring the Thumb-state bit in
the ELF function symbol. PR #61 corrects original and relocatable-object byte
extraction, chooses A32 versus Thumb from the authoritative symbol, and increments
the metric cache version. Contrary to an earlier diagnosis, DecBench does not
award a free perfect score when both disassemblies are empty; it falls back to raw
bytes. The concrete bug is mode/address handling.

I reran `byte_match` against the same stored Glaurung output using PR #61 rather
than carrying forward the main-branch numbers:

```text
decbench evaluate-tree fresh-materialized \
  --metric byte_match --decompiler glaurung --workers 12
```

The correction changed Glaurung's byte mean from `0.1845` to `0.2376`, the median
from `0.1305` to `0.2058`, perfects from 6 to 7, and zeros from 84 to 66. It also
removed one old byte-only union perfect; all seven corrected byte perfects overlap
a GED or type perfect. The corrected union is therefore 67, not 68.

This creates two reporting rules:

- use the PR #61 Glaurung byte results for diagnosis;
- do not treat byte head-to-head ranks as final until every published decompiler
  is recomputed under the same metric revision.

## 16:05–16:40 — projected scoreboard

This section records the original `c1cfdc97` projection. It is retained as diary
history, but its 59-GED/67-Union result is superseded by the fresh `9c25fcb`
replay in “03:00–03:45 — authoritative GED, union, and live-board placement.”

The scoreboard's headline is the percentage of evaluated functions perfect on at
least one metric. It is not the mean of the three metrics and it rewards exact
hits rather than broad partial quality.

| Projected rank | Decompiler | Union perfect | Evaluated | Percentage |
|---:|---|---:|---:|---:|
| 1 | Codex | 143 | 250 | 57.2% |
| 2 | Claude Code | 141 | 249 | 56.6% |
| 3 | angr | 72 | 220 | 32.7% |
| 4 | IDA | 70 | 234 | 29.9% |
| 5 | Kuna | 67 | 234 | 28.6% |
| 6 | Binary Ninja | 63 | 221 | 28.5% |
| **7** | **Glaurung** | **67** | **250** | **26.8%** |
| 8 | Ghidra | 59 | 234 | 25.2% |
| 9 | r2dec | 45 | 204 | 22.1% |
| 10 | dewolf | 13 | 171 | 7.6% |

Coverage denominators differ. Glaurung's 250-function denominator is complete;
several published tools abstain on functions or metrics. Rank therefore needs to
be read together with coverage and raw means.

Glaurung's corrected metric profile is:

| Metric | Perfect | Coverage | Perfect rate | Mean | Median | Zero |
|---|---:|---:|---:|---:|---:|---:|
| GED, lower is better | 59 | 239 | 24.69% | 32.46 | 10.0 | 59 |
| type match | 13 | 235 | 5.53% | 0.1740 | 0.0128 | 117 |
| byte match, PR #61 | 7 | 250 | 2.80% | 0.2376 | 0.2058 | 66 |
| union | 67 | 250 | 26.80% | — | — | — |

The headline narrowly exceeds Ghidra, but the distribution is weaker:

- Glaurung's GED mean is `32.46`; Ghidra's published mean is `25.64`.
- Glaurung's type mean is `0.174`; Ghidra's is `0.231`.
- On the 158 shared x86-64 byte cells, Glaurung's mean is `0.221`; Ghidra's is
  `0.311`.
- Glaurung has no unique union-perfect function: every one of its 67 exact wins
  is also exact for at least one published competitor.

The defensible verdict is “competitive lower-middle placement with unusually
complete coverage,” not “better decompilation than Ghidra.”

## 16:40–17:10 — architecture, optimization, and corpus splits

| Slice | Functions | Union perfect | GED mean | Type mean | Byte mean |
|---|---:|---:|---:|---:|---:|
| ARM32 ELF | 84 | 42.86% | 11.16 | 0.145 | 0.271 |
| x86-64 ELF | 158 | 19.62% | 43.16 | 0.195 | 0.221 |
| x86-32 PE | 8 | 0.00% | 19.38 | 0.0417 | 0.203 |
| O0 | 100 | 41.00% | 11.16 | 0.313 | 0.276 |
| O2 | 50 | 22.00% | 34.71 | 0.0764 | 0.255 |
| O2-noinline | 100 | 15.00% | 52.41 | 0.0955 | 0.191 |

ARM's strong union is mostly tiny CFG equality, not recovered source semantics:
51 of 76 scored ARM functions have type score zero, while 34 of 74 have GED zero.
The current ARM repair campaign was valuable, but it should not be mistaken for a
complete architecture-parametric analysis model.

Optimization is the more powerful predictor. O0 type mean is four times O2's,
and O2-noinline GED mean is nearly five times O0's. The current pipeline depends
heavily on compiler-preserved stack/register shapes and loses identity when
register allocation, lifetime reuse, CFG transformations, and inlining-related
shape changes become stronger.

## 17:10–17:35 — the function-size cliff

| Source-CFG node bin | Functions | Union perfect | GED mean | Type mean | Byte mean |
|---|---:|---:|---:|---:|---:|---:|
| under 10 | 36 | 83.33% | 3.17 | 0.302 | 0.445 |
| 10–49 | 118 | 29.66% | 9.55 | 0.201 | 0.267 |
| 50–99 | 22 | 4.55% | 24.52 | 0.102 | 0.195 |
| 100–249 | 53 | 1.89% | 59.53 | 0.109 | 0.112 |
| 250 or more | 21 | 0.00% | 146.25 | 0.104 | 0.0777 |

This is the central empirical finding. Glaurung is already effective on tiny
functions. Incremental opcode work can protect those wins, but it cannot close
the scoreboard gap. The missing capability is stable value, memory, and region
reasoning as graph size and optimization increase.

Projects with no union perfect include OpenSSH, sysvinit, U-Boot, x0r-usb,
findutils, libselinux, tar, both PE malware projects, and NuttX. GnuTLS has one
perfect in eleven and a GED mean of `132.82`.

## 17:35–18:15 — representative output traces

### `gnutls:O2-noinline:certtool:yyparse`

- source CFG size: 884;
- Glaurung: GED `601`, type `0`, byte `0`;
- best published competitor: GED `172`, type `0.30`;
- emitted function: 525 lines with a long declaration prelude, machine flags,
  stack aliases, and hundreds of numbered temporaries.

This is not an isolated wrong branch. It is a scaling failure across value
identity, DCE, region ownership, and source-variable construction.

### `coreutils:O2-noinline:cp:copy_reg`

- source CFG size: 590;
- Glaurung: GED `106`, type `0.118`, byte `0`;
- best published competitor: GED `26`, type `0.559`;
- emitted signature: 24 parameters;
- emitted function: 871 lines.

The source does not have 24 independent parameters. Register live-ins and
scratch/call lifetimes are being projected into source parameters because the
pipeline still reconciles physical storage, SSA sidecars, names, and recovered
types after the fact.

### `libopencm3:O0:usart_irq_console:console_getc`

The source is `char console_getc(int wait)`. Glaurung emits
`unsigned int console_getc(int *arg0)`, scoring type `0`. The body compares the
argument to zero; it does not dereference it. A later lifetime using the same
storage has contaminated the argument's type category. This is a compact
reproduction of the need for SSA-value-keyed type constraints and an explicit
function-input definition.

### `dpkg:O2:dpkg-statoverride:statdb_write`

The source is `static void statdb_write(void)`. Glaurung emits `long
statdb_write(void)` and ends in a synthetic `goto L_35d0` without a source-level
return. GED is `4`, byte is `0`, while another tool reaches byte `0.976` and GED
zero. A nearly correct CFG score can still hide a wrong function contract and
terminal structure.

### Global reference inconsistency

One fresh output declares and reads `glaurung_global_d0e8`, then writes the same
location as `*(int *)(0xd0e8)`. The raw address and named object are the same
program fact but reach the AST through different operand shapes. This is the
remaining core of EPIC 2: symbolization is broad over `Expr::Addr`, but it is not
yet a contextual reference service over exact machine values and use sites.

### Gate canaries

The broad regression gate remains valuable because aggregate metrics can improve
while individual semantics regress. Two known metric ratchets still need root
causes:

- `arith:gcc:O0.ged`: `0.0 -> 0.33`;
- `recursion:gcc:O2.ged`: `149.0 -> 199.5`.

Neither should be waived merely because the 250-function union moves upward.

## 18:15–18:55 — current architecture trace

The committed middle-architecture proposal remains directionally correct:
Glaurung needs an authoritative typed SSA/MIR between machine LLIR and semantic
HIR. The current code has made real progress since that proposal:

- all decompilation entry points share `prepare_llir_for_lowering` and
  `run_ast_passes` helpers;
- calls carry explicit register effects before SSA;
- `TypeMapV` adds SSA-value-keyed type evidence alongside the legacy map;
- explicit return values, conditional definitions, and a bit-demand oracle now
  exist;
- ARM32 frame/CFA aggregate coordinates and several wide arithmetic semantics
  are fixed;
- indirect jumps and conditional return forms exist; and
- DWARF stack-object bounds and aggregate typedef fields survive farther into
  lowering.

Those are substantive fixes. They also expose the remaining transitional seams.

### EPIC 1 — program-level symbols and types: foundation missing

There is still no `ProgramSession`, `ProgramEnv`, canonical symbol store, or
canonical type store in the decompiler path. Each top-level operation constructs
flat address maps, strings, readonly regions, function tables, DWARF contracts,
and callee caches. There are 68 object parse calls in 31 Rust files.

Addresses usually collapse to `HashMap<u64, String>`, losing range, kind, aliases,
relocation addends, import/thunk relations, authority, and conflicts. Recursive
`core::DataType`, debug-specific models, `TypeHint`, C type strings, and Python KB
records still lack one identity and precedence model.

### EPIC 2 — contextual constant references: partially delivered

`name_resolve` now walks calls, assignments, stores, returns, conditions, loops,
switches, casts, dereferences, and nested expressions. That is broader than call
targets and should be retained.

The semantic boundary is still `Expr::Addr` versus `Expr::Const`. Readonly folding,
string folding, function tables, and some architecture idioms reinterpret those
bits independently. Resolution has no operand/use ID, relocation provenance,
alternative interpretation, or symbol-plus-addend fact. The same address can
therefore render named on one path and numeric on another.

### EPIC 3 — aggregate recovery: useful debug path, no unified object model

DWARF/PDB-backed stack aggregates now retain bounds and fields more successfully,
including ARM current-SP/CFA unification. But the system still lacks stable
`ObjectId`, `TypeId`, access paths, a layout constraint solver, and semantic
field/index HIR shared by debug-backed and inferred layouts.

The benchmark sources heavily exercise field and indexed accesses. The source-CFG
extractor itself records many unsupported field nodes, so GED is not a complete
aggregate metric; type and byte behavior plus dedicated object-layout fixtures
must gate this work.

### EPIC 4 — architecture-parametric machine model: ARM32 remains second-class

Architecture identity remains split across `core::binary::Arch`,
`core::disassembler::Architecture`, and `ir::regview::Arch`. `regview` supports
only x86-64 and AArch64. ARM32 has a large lifter and ABI-specific repairs but no
shared register-view/alias contract with SSA and execution.

Scattered register strings and calling-convention matches still decide widths,
aliases, frames, and roles. ARM32 conformance requires one target model covering
A32/Thumb mode, endian, PC semantics, GPR/VFP register banks, soft/hard-float ABI,
stack/CFA rules, and explicit unsupported effects. The official
[AAPCS32](https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst)
is the contract, not x86-shaped generalization.

### EPIC 5 — definedness/reaching definitions: improved sidecars, no sound service

`BitDemandOracle` is a conservative and useful proof for demanded lanes. It is
not a general definition oracle. `use_def` is explicitly intra-block; SSA is a
sidecar over register storage; memory is not SSA-versioned; version-zero/live-in,
undefined, poison, unknown effects, and explicit function input are not one
queryable definition lattice; and `def_uses` exposes only the first output of a
multi-output intrinsic.

Several late AST passes still answer reaching-definition questions with local
maps and backward scans. The correct home is verified CFG-based MIR with complete
register and memory effects.

## 18:55–19:15 — code ownership and size

Current product-code measurements include Rust under `src/` and Python under
`python/glaurung/`:

| Scope | Files | LOC | Mean | Median | >1,000 LOC | >2,000 LOC | LOC in >1,000 |
|---|---:|---:|---:|---:|---:|---:|---:|
| product code | 656 | 362,707 | 552.9 | 302.0 | 73 | 21 | 47.9% |
| top-level `src/ir` modules | 58 | 104,114 | 1,795.1 | 997.5 | 29 | — | 85.4% |

Largest IR owners are `ast.rs` (16,268), `lift_x86.rs` (7,715), `call_args.rs`
(7,060), `types_recover.rs` (5,791), `stack_locals.rs` (5,390), `structure.rs`
(4,894), `lift_arm32.rs` (4,621), and `value_number.rs` (4,135).

Since the 2026-08-05 snapshot, product code grew by about 10,500 lines and 18
files. The mean stayed flat, but files above 1,000 lines increased from 71 to 73;
IR files above 1,000 increased from 27 to 29. The repair campaign is adding tests
and real capability, but local fixes are not improving composition.

Moving inline tests alone is insufficient. Production prefixes remain roughly
9,945 lines in `ast.rs`, 4,347 in `lift_x86.rs`, 3,185 in `call_args.rs`, 3,188 in
`types_recover.rs`, 2,541 in `structure.rs`, and 2,895 in `lift_arm32.rs`.

The responsibility mixtures are the real problem:

- `ast.rs` owns the model, lowering, semantic cleanup, verification, multiple
  renderers, declarations, output-specific preparation, and tests;
- lifters mix decoder adaptation, instruction families, register semantics,
  flags, ABI-adjacent policy, and tests;
- `call_args.rs` mixes ABI classification, reaching evidence, call rewriting,
  prototype policy, and rendering-facing repair;
- `types_recover.rs` mixes evidence, lattice decisions, ABI rules, prototype
  recovery, SSA reconciliation, and C spelling;
- `stack_locals.rs` mixes frame analysis, object discovery, coordinate systems,
  aggregate bounds, transformation, naming, and tests; and
- new HIR variants require many hand-written recursive walkers.

## 19:15–19:45 — primary-reference synthesis

The redesign is consistent with mature decompiler and compiler architectures:

- Ghidra's [P-code reference](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html)
  makes address space, offset, and exact size part of every varnode identity.
  Constants retain precision and only acquire interpretation from operations.
- Binary Ninja separates lifted IL, LLIL, LLIL SSA, typed MLIL/MLIL SSA, and
  structured HLIL; its [official BNIL overview](https://docs.binary.ninja/dev/bnil-overview.html)
  explicitly assigns variables, types, calls, and data flow to the middle layer.
- LLVM [MemorySSA](https://llvm.org/docs/MemorySSA.html) uses explicit memory
  definitions, uses, and phis plus a clobber walker, while deliberately trading
  precision for speed. Glaurung should start with conservative regions rather
  than demand perfect alias analysis before gaining sound memory versions.
- [Retypd](https://arxiv.org/abs/1603.05495) demonstrates that machine-code type
  recovery needs constraints, recursive types, subtyping, and polymorphism;
  [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf) derives
  conservative types from use and control-flow evidence. Both argue against a
  flow-insensitive last-hint-wins map keyed by physical register name.
- Phoenix's [semantics-preserving structural analysis](https://edmcman.github.io/papers/usenix13.pdf)
  treats preservation as an explicit property; DREAM's
  [pattern-independent structuring](https://www.ndss-symposium.org/ndss2015/ndss-2015-programme/no-more-gotos-decompilation-using-pattern-independent-control-flow-structuring-and-semantics/)
  shows why a growing bag of local CFG shapes does not scale. Glaurung should
  use graph boundaries and retain honest gotos when proof fails.
- Current [Kuna](https://github.com/Noelo-Lab/kuna/tree/82dd39a72b04d7df9b0e5ae15d58727a670e34c4)
  organizes the engine into explicit knowledge, lift, data-flow, variable,
  structure, and emission phases with stable program/function substrates. Its
  large files are not a layout template, but its semantic identities and phase
  contracts are useful comparison points.

## Final findings register

Ranked by expected correctness and scoreboard leverage:

1. **Large optimized functions collapse.** The 0% union-perfect rate at 250+
   nodes and O2-noinline GED mean of 52.4 dominate the gap.
2. **Function contracts are unsoundly reconstructed.** Phantom parameters,
   pointer/scalar contamination, and wrong void/return decisions suppress type,
   byte, and often GED together.
3. **There is no authoritative value/memory definition service.** Existing SSA,
   bit demand, and local reaching maps solve subsets but cannot safely compose.
4. **Program facts are rebuilt and flattened.** This causes inconsistent symbols,
   duplicate work, weak interprocedural types, and non-reusable analyst knowledge.
5. **The structurer scales by accumulated shape rules.** Shared joins, large loops,
   switches, and unresolved transfers produce declaration and goto explosions.
6. **ARM32 correctness improved without architectural parity.** The score proves
   the fixes, while register/model seams show the next architecture would repeat
   the campaign.
7. **Aggregate recovery is metadata-specific.** There is no common object/access
   model for debug, inference, calls, and rendering.
8. **Contextual references remain lossy.** The same address can become a named
   object or a raw integer depending on AST path.
9. **The implementation is concentrating, not decomposing.** Nearly half of all
   product LOC and 85% of IR LOC live in files above 1,000 lines.
10. **Performance is dominated by repeated setup and rescans.** A session, shared
    indices, pass change sets, and dependency-aware caches should precede local
    representation tuning.
11. **Metric-only optimization is unsafe.** GED has known parser blind spots and
    the canary gate already found two regressions invisible in the headline.
12. **The submitted placement is provisional.** PR #56 is not merged, PR #61 is
    not merged, and no published competitors have been recomputed under #61.

The companion roadmap converts these findings into dependency-ordered work with
tests, metric targets, performance budgets, file-size fitness checks, and stop
conditions.

## 22:05–22:40 — Phase 0 implementation: reproducible score ledger

The original gap analysis was reproducible only while its scratch result tree and
one-off analyzer survived under `/tmp`. I converted that evidence into a checked-in,
fail-closed experiment contract:

- `tests/decbench_scoreboard/manifest.json` pins the three repository revisions,
  the PR #61 byte-metric implementation and source hash, evaluation-kit identity,
  tool versions, raw ZIP checksum, all 250 ordered function keys, and overlapping
  worst/perfect canary sets;
- `tools/decbench_score_ledger.py` recomputes aggregates from the 250 function rows
  instead of trusting stored summary fields;
- the ledger now reports architecture, optimization, CFG-size, and head-to-head
  slices in addition to headline statistics; and
- the checked-in canonical ledger is byte-identical across repeated runs.

Two contract errors were found during TDD. First, regenerating the “stable” canary
set from every new score would reject the very improvements the canaries are meant
to observe. The manifest now owns immutable identities and the ledger reports their
current metrics. Second, requiring the baseline Glaurung revision on every run would
make before/after comparison impossible. Dataset, DecBench, function denominator,
and metric schema remain pinned; Glaurung is the explicit independent variable.
`--check-baseline` restores exact-revision checking when reproducing the baseline.

The verified baseline remains 59 GED perfects, 13 type perfects, seven PR #61 byte
perfects, and 67 union perfects. The two canonical runs produced the same SHA-256,
`14df97b5e11bfc674893a1c57dd08297fb98c1b6a51884d14cbbbe13be3e5e5d`.
The raw package checksum also matched. This phase changes no decompiler semantics.

One reproducibility caveat is now explicit instead of inferred: the evaluation kit
ships prebuilt binaries but does not record their compiler versions. The dataset
revision and kit manifest hash identify those binaries, but a future kit revision
must capture compiler identities before compilation.

## 22:45–23:25 — Phase 0 implementation: pass-attributed output health

The old `GLAURUNG_DUMP_PASSES` stream was useful to a person but unsuitable for a
regression ledger: it rendered large C bodies, had no schema, and could not say
which pass first changed a measurable risk. I added an opt-in JSONL trace at the
single shared AST pipeline and at the DecBench preparation/render boundaries.
The counters are computed from the AST and the production definition oracle, not
from regular expressions over emitted C.

The trace now records parameters, declarations, temporaries, raw physical
registers, named definition violations, gotos, unresolved transfers, recursive
statement count, uncovered and invented CFG edges, and verified-structuring
fallbacks. Region recovery carries CFG fidelity explicitly into the AST pipeline.
The edge counters describe the region actually emitted: rejecting an unsound
candidate in favor of labelled CFG increments `structure_fallbacks` but does not
misreport the lossless fallback as having missing edges.

`tools/pass_health_report.py` rejects missing, stale, or malformed evidence,
groups events per function, attributes the first change in each counter and the
first appearance of each final violation, and optionally computes the
output/source-CFG size ratio. Its canonical JSON is byte-stable.

The real `hello-gcc-O0:main` canary produced 22 pipeline events from a 22-block
source CFG. The final AST has 69 statements (ratio `3.136`), 41 declarations, 35
temporaries, two gotos, no physical registers, no unresolved transfers, and zero
uncovered or invented CFG edges. It also exposed two final never-defined values,
`var105` and `var93`; both first appear at `apply_role_names`. This is a concrete
semantic lead for the later definedness/value-identity phase, not merely a new
counter.

The integration test runs the checked-in binary with tracing enabled and disabled,
requires byte-identical stdout, and requires no health prefix in the disabled
stderr. All 1,876 Rust library tests pass, as do all 14 focused ledger/health
Python tests. The full Python suite reached 100% and retained exactly four known,
unrelated `test_suspicious_symbols` fixture failures: those cross-compiled
`suspicious_win-*` samples contain none of the APIs that their test requires,
even under its final raw-byte fallback. Repository-wide Ruff and ty remain
non-green at their pre-existing 3,710 and 2,159 diagnostics respectively; both
are clean on the new Python files. Phase 0 still needs the seven named
score/output canaries and the cold/warm resource baseline before it closes.

## 23:25–23:55 — Phase 0 implementation: resource and pipeline baseline

Callgrind on the checked-in `hello-gcc-O0:main` first showed 3,679 calls to
`object::read::File::parse`; 3,541 originated below
`analysis::entry::va_to_code_file_offset`. That was strong but external evidence,
and it could not cheaply measure every corpus shape. I routed all 67 direct Rust
call sites through one transparent `parse_object` adapter and added an opt-in
`GLAURUNG_PIPELINE_PROFILE=1` JSONL stream at the four public decompilation entry
points and the already-shared AST/render pipeline. The adapter still delegates
directly to `object`; it changes no ownership or caching semantics yet.

The native count for the same function is exactly 3,679, independently matching
callgrind. Profiling enabled and disabled produce byte-identical C. The parser and
benchmark tools fail closed on missing or stale events, use fresh worker processes
for cold measurements, repeat queries in one process for warm measurements, hash
every output, and record process RSS. Nested and concurrent runs are isolated by a
thread-local monotone parse counter; an outer run includes nested work while each
nested run retains its own delta.

The clean-revision `4b6838f` baseline covers five real binaries:

| Case | Cold | Warm median | RSS cold/warm | Parses per query |
|---|---:|---:|---:|---:|
| `hello-gcc-O0:main`, small x86-64 | 289.3 ms | 98.8 ms | 88.0 / 87.7 MiB | 3,679 |
| DecBench `bin_039:copy_reg`, stripped x86-64 | 1,049.8 ms | 946.5 ms | 92.7 / 93.9 MiB | 16,225 |
| DecBench `bin_093:yyparse`, large stripped x86-64 | 901.2 ms | 707.7 ms | 119.2 / 119.2 MiB | 18,252 |
| DecBench `bin_110:console_getc`, ARM32 | 17.5 ms | 16.5 ms | 49.5 / 49.7 MiB | 188 |
| `hello-rust-debug:main`, debug-heavy | 1,395.3 ms | 1,205.4 ms | 108.8 / 128.4 MiB | 22,873 |

All three warm outputs per case have one hash, and every warm parse count equals
the cold count. Warm process state therefore amortizes imports and lazy globals,
but no binary/session analysis. The scale of repeated parsing tracks binary
analysis breadth rather than function AST size: the tiny Rust `main` triggers
22,873 parses because the debug-heavy image is repeatedly reopened by program
fact consumers.

The stage trace found a second, independent cold-path cost. The first x86-64
`apply_known_call_contracts` takes 187–191 ms because a failed libc lookup lazily
deserializes the 19.7 MB, 20,764-entry WinAPI JSON catalog. ARM32 does not reach
that fallback in this corpus. The durable fix is target-aware catalog ownership
in `ProgramEnv`; preloading the catalog would merely move the same cost earlier.

The production extension exposes no allocator counter. The artifact records this
as unavailable; it does not present Python allocator data as native allocations.
The complete machine-readable baseline, binary hashes, output hashes, stage times,
host facts, and exact rerun command live under `tests/decompiler_profile/`.

Validation at this checkpoint: 1,880/1,880 Rust library tests pass, all 13 focused
profile/health Python tests pass, focused Ruff and formatting are clean, and the
remote branch contains the instrumentation commits. Phase 0 now has one remaining
task: materialize the seven named score/output canaries.

## 23:55–00:20 — Phase 0 closure: named output canaries

The remaining Phase 0 task is now a checked, executable gate rather than a list of
interesting names. `tests/decompiler_output_canaries/manifest.json` pins four
official sample-set binaries by SHA-256 and three locally built cells by source
hash, exact compiler version, and flags. The seven cases cover eleven concrete
functions:

- official: `copy_reg`, `yyparse`, `console_getc`, and `statdb_write`;
- `arith:gcc:O0`: `addmul`, `shifts`, and `signs`;
- `recursion:gcc:O2`: `ackermann` and `fib`; and
- `linkedlist:clang:O0`: `list_find` and `list_sum`.

For each function the baseline records the resolved entry, signature, byte and
line count, output SHA-256, final health counters, final definition violations,
and first-introducing pass. Two complete captures were byte-identical. The final
baseline is rooted at clean revision `f163e34`, has SHA-256
`8cd9624620ef55b7133aa2117dbe303158c0129c9aa8b81de42e187ec03728a4`, and the
check regenerates all eleven observations.

The gate preserves the defects we intend to repair as visible evidence rather
than normalizing them away. `copy_reg` currently has 24 parameters, 175
declarations, 91 gotos, 593 statements, one physical register, and six undefined
uses. `yyparse` has five parameters, 111 declarations, 54 gotos, 378 statements,
two physical registers, and 27 undefined uses. `console_getc` still renders
`unsigned int sub_80002f8(int * arg0)` instead of `char console_getc(int wait)`,
and `statdb_write` still renders `long sub_4800(void)` with one goto. All eleven
functions nevertheless have zero uncovered and zero invented CFG edges, so later
improvements can distinguish output simplification/type repair from lost control
flow.

`tools/decompiler_output_canaries.py` fails on missing external inputs, source or
binary hash drift, compiler drift, missing symbols, empty output, absent health
events, or any baseline field change. It reports the exact case, function, and
field that moved. Baseline refresh is therefore an explicit review action, not an
automatic side effect of a test run.

With the score ledger, pass attribution, resource baseline, and focused canaries
all materialized, Phase 0 is complete. The next implementation phase is the
single-owner `ProgramImage`/`ProgramSession` seam; its first measured acceptance
target is reducing one session from 188–22,873 base parses to exactly one while
keeping every canary output byte-identical.

The repository-wide Python gate completed after the canary baseline was added.
It retained exactly the same four unrelated `test_suspicious_symbols` failures
already documented above (the riscv64, armhf, arm64, and exported-riscv64
`suspicious_win-*` binaries contain none of the APIs the test requires, including
under its raw-byte fallback). No new failure appeared. The focused canary suite is
4/4 green, and the combined ledger/health/profile/canary suite is 26/26 green.

## 00:20–00:50 — Phase 1 increment: one indexed program image

I introduced `ProgramImage` as an owned, immutable base-image index and routed
the CFG, targeted-callee, lifter, and four Python decompilation entry points
through it. The image owns the input bytes and records format, architecture,
endianness, entry address, ARM hard-float metadata, file-backed segment and
section mappings, executable ranges, and defined-symbol indices after one base
parse. Existing byte-oriented Rust APIs remain compatibility adapters; new image
APIs let one caller carry those facts through discovery and lifting without
reopening the object for every address translation.

The first implementation deliberately stops short of claiming a complete
`ProgramSession`. Relocation, read-only-range, debug-handle, environment, and
analysis-cache ownership still live in their existing modules, and 47 secondary
object parses remain on the measured x86-64 query. The remaining calls are now
bounded analysis consumers rather than the former instruction-proportional
address mapper. `ProgramSession`, typed partial artifacts, a shared engine, and
the direct-object-parse dependency gate remain Phase 1 work.

The real `hello-gcc-O0:main` regression went RED against the old extension at
3,679 parses. After the migration it records 47 parses per query, a 98.7%
reduction. Against the clean same-host baseline, cold decompilation moved from
289.3 ms to 273.8 ms (5.3% faster), and the three-run warm median moved from
98.8 ms to 82.5 ms (16.5% faster). Cold/warm maximum RSS is 88.3/87.8 MiB,
effectively unchanged. Every run retained output SHA-256
`edf693bfb1168a2b70f73cffa662437c49b9d14c6d3576d6c54390d89b22c014`.

The complete same-host five-shape rerun improved every measured cold and warm
time while preserving one output hash per case:

| Case | Cold before/after | Warm before/after | Parses before/after |
|---|---:|---:|---:|
| small x86-64 | 289.3 / 273.8 ms | 98.8 / 82.5 ms | 3,679 / 47 |
| stripped x86-64 | 1,049.8 / 992.5 ms | 946.5 / 801.1 ms | 16,225 / 55 |
| large stripped x86-64 | 901.2 / 842.4 ms | 707.7 / 638.1 ms | 18,252 / 33 |
| ARM32 | 17.5 / 17.3 ms | 16.5 / 16.2 ms | 188 / 32 |
| debug-heavy Rust | 1,395.3 / 1,298.4 ms | 1,205.4 / 1,089.4 ms | 22,873 / 22 |

The reductions range from 1.3–6.9% cold and 2.0–16.5% warm. This is not yet the
promised reusable-session speedup: compatibility calls still construct a fresh
image, so warm runs save initialization but repeat image and analysis work.

Eight Rust tests cover malformed input, checked address arithmetic, real ELF,
PE, ARM32/Thumb and hard-float metadata, legacy address parity, CFG parity, and
LLIR parity. The exact eleven-function output-canary gate passed without a
baseline refresh. All 1,888 Rust library tests and every Rust integration test
passed; all eight focused Python profile/harness/canary tests passed. Focused
Ruff formatting and lint are clean through the repository's `uvx` tool path.
Targeted `ty` remains non-green only on its three existing missing-attribute
diagnostics for `pytest.fixture`, `pytest.mark`, and `pytest.raises`; it reports
no diagnostic in the new test body.

## 00:50–01:05 — fresh-corpus replay and the next parse owner

The first image increment was committed as `45b233cf818ad07454bf87a1feedd7b2af90a75d`.
I discarded the prior score artifacts as evidence for that revision and rebuilt
all 122 available project/optimization cells. The rebuilt tree contains 880
binaries and 11,909 preprocessed `.i`/`.ii` sources. The official 250-function
membership was resolved independently against its manifest before decompilation;
all 250 keys map to ground-truth functions. Two evaluation lanes then started:

- the authoritative sample-set lane imports fresh raw output from all 224
  stripped kit binaries into a clean copy of the pinned official unstripped
  source/DWARF tree;
- a diagnostic lane runs the same Glaurung revision over the rebuilt modern
  corpus to expose compiler- and corpus-shape drift, without presenting those
  results as directly comparable to the public board.

The raw sample-set extraction returned 250/250 requested functions from 224/224
binaries with zero invocation failures. The package SHA-256 is
`c08c3985591b97dc6f9ff0fa7602bf5aacfb94feb14829842d4b86231d485096`.
The scorer must use the separate unstripped tree: the eval-kit binaries are
intentionally stripped and therefore cannot provide their own DWARF ground
truth. This distinction is now an explicit replay invariant rather than an
ambient evaluator assumption.

The remaining object parses after `ProgramImage` were traced to two whole-image
collectors in every Python entry point. `collect_string_pool` and
`collect_readonly_data` reopened the object even though the image already owned
the validated section ranges. The next additive increment indexes file-backed
section name, address, and byte range once in `ProgramImage`, exposes borrowed
`ProgramSection` views, and gives both collectors image-based adapters sharing
their existing section semantics. Real ELF, ARM32 ELF, PE, and Mach-O fixtures
prove exact parser parity, while the legacy byte APIs remain compatibility
adapters. This removes two repeated base parses per decompilation without adding
another object owner.

## 01:05–01:20 — ARM32 alignment padding is not argument evidence

The fresh official trace exposed a concrete type-recovery defect in
`cleanflight:clang:O0:serialWrite`. Its source contract is
`void serialWrite(serialPort_t *instance, uint8_t ch)`, but stripped Glaurung
rendered four parameters:

```c
int *sub_80101b4(int *arg0, long arg1, long arg2, int *arg3)
```

The machine function begins with Thumb `push {r3, lr}` and ends with the balanced
restore. GCC is using caller-saved `r3` only as four bytes of padding to preserve
the ARM ABI's eight-byte public stack alignment. The LLIR live-in scan treated
the initial store of `r3` as a genuine read, selected argument slot 3, and the C
signature planner filled every positional slot through `arg3`. This is a general
machine-model boundary defect: a storage read is not necessarily a source-level
function input.

The checked-in real ARM fixture `hello-armhf-gcc:_fini @ 0x5d4` reproduces the
same `push {r3, lr}` / `pop {r3, pc}` shape and went RED with inferred slot set
`{3}`. The repair suppresses only the particular `r3` store when the same LLIR
block proves all of the following: ARM/AAPCS calling convention, a same-VA
adjacent link-register save, an exact same-slot `r3` restore, no post-restore
`r3` read, no call or indirect transfer, and an unconditional return. An
intervening genuine `r3` read is still seen by the ordinary first-touch scan. A
near-miss test restores and consumes `r3` and proves slot 3 remains parameter
evidence.

The focused real and negative tests are green, and the complete Rust library
gate is 1,895/1,895. The Python extension, exact output canaries, profile matrix,
and score cell remain deliberately unrefreshed until the revision-pinned
baseline evaluation processes release the installed executable.

## 01:20–01:35 — measured candidate behavior and rejected score evidence

After the revision-pinned diagnostic lane released the executable, the candidate
extension was rebuilt from the dirty worktree and its loaded native-module path
was verified. The real outputs changed exactly as predicted:

| Function | Before | Candidate |
|---|---|---|
| `hello-armhf-gcc:_fini` | four positional parameters | `void _fini(void)` |
| `cleanflight:serialWrite` | four positional parameters | one evidenced pointer parameter |

The corrected type metric for `serialWrite` remains `0.0`: the source has a
second pass-through `uint8_t` argument whose value is never defined in this
function, and stripped Glaurung does not yet have a sound indirect-call
prototype or aggregate-field owner from which to recover it. Nevertheless, the
metric confusion matrix moves from two false positives to one false positive plus
one false negative, and the emitted contract no longer claims three unsupported
inputs. This is a safety/correctness repair, not a score win. Inferring all
untouched AAPCS call registers would merely recreate the same phantom-parameter
bug; the next score-bearing owner is value-keyed indirect-call prototype evidence
from `ProgramEnv`/aggregate access paths.

The image-section increment reduces the real small-x86 query from 47 to exactly
45 object parses, matching the two migrated collectors. Its cold time is 278.1
ms and three-run warm median is 85.3 ms; both remain within the Phase-1 ceiling
and the output hash is unchanged. All eleven high-risk output canaries are
byte-identical. Eighteen focused ARM/ILP32/definedness Python tests and the full
Rust suite, including every integration test, pass.

The ARM classifier lives in the focused 149-line `arm_input_evidence` module
instead of adding another machine-idiom subsystem to the 4,000-line
`value_number` owner. A third near-miss test proves that even a balanced save and
restore is not suppressed when the suffix contains conditional control flow;
the classifier now requires a straight-line, unconditional return.

The first authoritative sample-set scoring attempt is rejected in full. While
the old worktree-local Rust target occupied `/tmp`, PyJoern exhausted that
filesystem's quota during the latter projects and logged source-CFG extraction
and evaluation failures. A zero process exit does not make those partial metrics
valid. The 224/224 raw package remains valid because extraction had completed
before scoring and does not use PyJoern. Scoring is being rerun from that package
with `TMPDIR` on the main disk; acceptance requires the evaluator audit to prove
all 250 manifest functions, the expected metric denominators, and zero evaluation
failures.

The rebuilt-modern diagnostic lane completed independently with 224 binaries and
241 resolved manifest rows; nine official names were renamed or removed in the
new builds. Its initial 27.8% union is explicitly provisional because finalization
reported all three corrected overlay files missing. Re-evaluation, not the inline
checkpoint columns, is the required evidence for that lane.

## 02:00–02:25 — current-revision kit and corrected metric controls

The section-index and ARM-input increment was committed and pushed as
`9c25fcb860fb433b59bb24b3f880e8ae3a38a972`. Local HEAD, the tracking ref, and
the live remote ref matched exactly. Its final gates were 1,895/1,895 Rust
library tests plus every integration target and doc test, 18 focused Python
tests, all 11 output canaries, `cargo fmt --check`, and `git diff --check`.

Because `9c25fcb` advanced the implementation while the fresh `45b233cf`
baseline was scoring, I built a second blinded submission instead of presenting
the baseline as current. A clean DecBench export attempt failed because the host
`strip` could not recognize the ARM cleanflight input. The fallback did not
substitute or restrip binaries: it copied the already-verified blinded kit while
excluding every generated result, log, diagnostic, cache, and package. All 224
binary hashes and the `functions.json` hash match the baseline kit, the result
directory began empty, and both live driver contract tests passed.

The full current extraction returned exactly 250/250 functions from 224/224
binaries in 228 seconds with zero errors. `package.py` independently accepted
the package; its SHA-256 is
`ac6e092cbfb74cd61177d1a402d424bce6ac057401f8e9b45dd92f0018f79700`.
Only five of the 224 emitted C artifacts differ from `45b233cf`, all ARM32:
cleanflight O0 and O2-noinline, betaflight O0 and O2, and RIOT-OS O0. The other
219 artifacts are byte-identical.

The corrected type and byte overlays were run independently for both revisions
on separate copies of the frozen 250-function ground-truth tree:

| Metric | Coverage | `45b233cf` | `9c25fcb` | Per-function delta |
|---|---:|---:|---:|---:|
| type-match mean | 235 measurable | 0.17399256 | 0.17399256 | 0/235 changed |
| type-match median | 235 measurable | 0.01282051 | 0.01282051 | 0/235 changed |
| byte-match mean | 250 | 0.23761268 | 0.23761268 | 0/250 changed |
| byte-match median | 250 | 0.20578221 | 0.20578221 | 0/250 changed |
| recompiles | 250 | 208 (83.2%) | 208 (83.2%) | 0/250 changed |

Type-match has 13 perfect rows and 117 zero rows; byte-match has 7 exact rows
and 66 zero rows. This proves the ARM repair is score-neutral on the two
completed official metrics: it removes unsupported inputs without buying a
metric win or introducing an emission regression.

The aggregate hides a useful architectural split. Type-match averages 0.1953
on 151 x86-64 rows, 0.1455 on 76 ARM32 rows, and 0.0417 on eight PE32 rows.
Optimization is an even stronger separator: O0 averages 0.3131, O2-noinline
0.0955, and O2 0.0764. By contrast, ARM32 is the strongest byte-match group:
0.2714 mean with 82/84 recompiling, versus x86-64 at 0.2214 with 118/158
recompiling. The evidence does not support treating ARM lifting or emission as
the single dominant problem. ARM/PE types and optimized cross-function type
evidence are the sharper boundary: exactly the territory owned by program-level
prototypes, reaching definitions, stack objects, and aggregate recovery.

The byte overlay required an additional reliability control. Its resumable
driver treats a checkpoint filename as sufficient and does not compare its
mtime or input content, unlike the GED driver. A cloned score tree initially
reported zero pending tasks and silently reused the `45b233cf` byte results.
That output was rejected. Re-running all 224 tasks in a revision-specific
checkpoint directory produced the accepted `9c25fcb` figures above. Any future
benchmark automation must make metric caches content-addressed by the emitted C,
binary, metric version, and toolchain; a revision label alone is insufficient.

The first all-source corrected GED attempt was stopped and is not accepted as a
result. Source-CFG extraction covered 3,747 preprocessed translation units and
wrote project caches only after the whole extraction stage, so an interrupted
run lost its in-memory partial progress. The completed target-aware replay below
supersedes this in-progress note.

A read-only ownership walk quantified the avoidable work. Using the frozen
manifest plus each selected binary's `DW_AT_decl_file`, 242/250 target functions
resolve to only 188 unique `(project, source file)` owners. The eight unresolved
targets are confined to dexter, mydoom, and x0r-usb; scanning every O0
preprocessed unit in those three fallback projects adds only 19 files. A
target-aware source-CFG plan therefore appeared to need at most 207 candidate
units instead of 3,747. The executed coverage-checked plan required 454 units;
the completed measurements and why the bound expanded are recorded next.

## 03:00–03:45 — authoritative GED, union, and live-board placement

The corrected GED replay is complete for both the `45b233cf` baseline and the
current `9c25fcb` candidate. The source-cache builder changed only source-unit
selection: it called the same `extract_cfgs_from_source` parser as DecBench and
the final metric run used the unmodified `scripts/reeval_ged.py` scorer. No
Glaurung result checkpoint was shared between revisions.

The cache build resolved 242/250 manifest functions through binary DWARF. Its
first pass selected 223/3,794 preprocessed units. A manifest-level CFG coverage
check then rejected three under-selected projects and conservatively expanded
all units for coreutils, libopencm3, and RIOT-OS. The accepted cache contains 454
translation units, an 88.0% reduction from an all-source pass. Five source CFGs
remain explicitly unavailable even after fallback:

- `coreutils:compare_files`;
- `libopencm3:__swrite`;
- `riot-os:__swrite`; and
- `u-boot:fs_ls_generic` plus `u-boot:mmc_send_ext_csd`, whose project has no O0
  source tree in this materialization.

The unchanged scorer started from zero GED checkpoints for each revision and
processed all 224/224 binary slices. Both revisions produced exactly the same
243 function results and the same value for every function:

| GED result | `45b233cf` | `9c25fcb` | Delta |
|---|---:|---:|---:|
| measured | 243 | 243 | 0 |
| perfect | 60 | 60 | 0 |
| perfect rate | 24.69% | 24.69% | 0 |
| mean edit distance | 23.7942 | 23.7942 | 0 |
| median edit distance | 10.0 | 10.0 | 0 |

The two additional unmeasured rows beyond the five source misses are
decompiled-C CFG parse misses: `cleanflight:serialWrite` and
`freertos:Default_Handler`. They are absent rather than assigned favorable
values. The five changed ARM artifacts in `9c25fcb` therefore have no structural
score effect, which is consistent with a prototype-evidence correction that does
not change control flow.

Directly joining the three fresh, revision-specific overlays on the frozen
manifest gives the current result:

| Metric | Perfect | Measured | Perfect rate | Mean | Median |
|---|---:|---:|---:|---:|---:|
| GED distance, lower is better | 60 | 243 | 24.69% | 23.7942 | 10.0 |
| type-match score, higher is better | 13 | 235 | 5.53% | 0.17399 | 0.01282 |
| byte-match score, higher is better | 7 | 250 | 2.80% | 0.23761 | 0.20578 |
| union | 69 | 250 | 27.60% | — | — |

The union is independently reproducible from the exact-win sets: GED contributes
60, type contributes 13, and byte contributes seven; GED/type overlap on five,
GED/byte overlap on five, and type/byte overlap on one, with no triple overlap.
`serialWrite` is the single byte-only win. Raw byte checkpoints contain all 250
functions and 208 recompilable outputs (83.2%). The derived function-data layer
drops the non-perfect `freertos:Default_Handler` byte row, so its 249-row compile
rate must not replace the complete raw-overlay denominator.

Against the live `sample-set|0` aggregate generated at
`2026-08-09T03:22:00.811118`, adding Glaurung produces this Union ordering:

| Projected rank | Decompiler | Union perfect | Denominator | Rate |
|---:|---|---:|---:|---:|
| 1 | Codex | 143 | 250 | 57.2% |
| 2 | Claude Code | 141 | 250 | 56.4% |
| 3 | angr | 71 | 250 | 28.4% |
| 3 | IDA | 71 | 250 | 28.4% |
| 5 | Kuna | 70 | 250 | 28.0% |
| **6** | **Glaurung** | **69** | **250** | **27.6%** |
| 7 | Binary Ninja | 63 | 250 | 25.2% |
| 8 | Ghidra | 58 | 250 | 23.2% |

Thus Glaurung is one exact function behind Kuna, two behind angr/IDA, six
functions/2.4 points ahead of Binary Ninja, and 11 functions/4.4 points ahead of
Ghidra on the actual headline definition. It would rank sixth overall and fourth
among traditional
decompilers. This remains a projection until PR #56 is accepted and the
maintainer publishes Glaurung; Glaurung is not yet a live scoreboard row.

Canonical finalization exposed two DecBench integration caveats rather than a
metric uncertainty. `finalize_results.py --audit` reports zero `SILENT-DROP`
findings after the write and five explicit GED `OVERLAY-GAP`s corresponding to
the source misses above. Direct inspection confirms those five published rows
contain type/byte values but no stale GED value. However, this evaluator branch
does not repopulate `FunctionData.metrics`/`perfect_values` from external
overlays, so its generated
`scoreboard.toml` has an empty metric registry even though
`function_results.json` holds the values. It also omits the one byte row named
above. The 69/250 result therefore comes from the primary overlay artifacts, not
that malformed derived TOML. Those publisher defects must be fixed in the
submission integration before an upstream render; they do not alter the joined
perfect sets or the Glaurung baseline/current equality.

## 04:00–04:20 — first owner-grouped type repair

The fresh type overlay contains exactly 29 functions at edit distance one. They
are now pinned in `tests/decbench_scoreboard/type-distance-one-9c25fcb.json`,
including the source overlay SHA-256
`4cbb9613344bf365df9cc6c8e72993a62eb1d14a360576daa89736d991cf596c`.
The executable corpus contract requires 29 unique keys grouped by semantic
owner: 20 pointer-category failures, six missing-local identities, two integer
widths, and one missing parameter. This closes the roadmap's corpus task while
leaving 28 rows explicitly open.

The first repair targets ChibiOS `nvicEnableVector(uint32_t n, uint32_t prio)`.
Its exact `r0#0` value is consumed by LSR (`n >> 5`) and also participates in a
derived MMIO address. Pointer propagation previously won the raw-register merge
and rendered `char *`. The valued type engine already treated LSR as exact
unsigned evidence after an O0 spill/reload, but direct live-ins never crossed
the qualified parameter-evidence boundary. One shared AAPCS live-in predicate
now covers both paths and requires SSA version zero, so later scratch lifetimes
cannot qualify a source parameter.

Evidence is RED/GREEN at three levels:

- the new LLIR regression failed with `Pointer { pointee_width: 1 }` before the
  repair and passes as unsigned four-byte integer afterward;
- all 54 `ir::types_recover::tests` pass, including the existing ARM spill path
  and the x86 isolation control; and
- the real stripped kit binary now emits
  `void nvicEnableVector(uint32_t arg0, uint32_t arg1)`. The unmodified official
  `TypeMatchMetric` reports `1.0`, `tp=2`, `fp=0`, `fn=0`, replacing the pinned
  `0.5`/distance-one result.

A fresh static extraction covered 250/250 requested functions across all
224/224 kit binaries. Compared byte-for-byte with the accepted `9c25fcb`
submission, 248 function artifacts are unchanged. The only changes are
`nvicEnableVector` and `spekShouldBind`'s inferred declaration for `IOGetByTag`;
DWARF identifies that callee's source argument as the unsigned `ioTag_t`
(`uint8_t`), so changing its declaration from signed to unsigned is directionally
correct. `spekShouldBind` retains exactly its prior type score `0.0`/distance two
and byte score `0.3529411765`/distance 33. `nvicEnableVector` remains byte score
zero, so this increment raises type perfects from 13 to 14 but does not raise the
69-function union: that function was already one of the 60 perfect GED rows.

The first focused GED attempt was not accepted: that evaluator environment
lacked Joern and attempted a 1.79 GB bootstrap, which was stopped. Re-running in
the provisioned evaluator environment gives `nvicEnableVector` GED `0.0`
(perfect) and `spekShouldBind` GED `14.0`, exactly matching their prior values.
The mandatory five-lane decompiler gate also passed without a waiver: full Rust
tests, x86 differential fixtures, the AArch64/ARMv7/A32/i386/control round trip
(1,757 passes and the same 43 known failures), both executable behavior
matrices, and no per-cell regression across all 56/56 GED/type/byte cells.

The repository-wide Python run completed with 2,871 passes, 44 skips, and four
failures in `test_suspicious_symbols_if_present`. Those four are a pre-existing
fixture-selection defect, not a type-recovery regression: discovery uses
unsorted recursive traversal and truncates at eight, so this worktree selected
four cross-built `suspicious_win` ELF files that contain none of the required
APIs. A detached build of parent `11041a8` produces identical symbol/import
results and all four assertions fail when invoked directly against the same
byte-identical fixtures. The parent file-level run happens to pass because its
filesystem traversal selects eight different fixtures. The new corpus contract
passes scoped Ruff format/lint and `ty`; repository-wide Ruff formatting remains
red on 309 pre-existing files and repository-wide `ty` reports 2,063 existing
diagnostics, so neither unrelated baseline was rewritten in this increment.
