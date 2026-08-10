# Glaurung DecBench gap-analysis diary — 2026-08-08

**Status:** original pinned evidence complete; fresh baseline/current replay complete

**Companion plan:** [decbench-remediation-roadmap-2026-08-08.md](decbench-remediation-roadmap-2026-08-08.md)

**Glaurung:** `c1cfdc97fdf51a5028aff5f7507033d70d16ad42`

**Current stripped-kit candidate:** `06b2e614a6b84e96e594daf23933376078fe1092`

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

## 05:20–06:15 — fresh type-corpus replay and value-keyed call contracts

The 29-row distance-one file was a valid historical cohort but a stale status
ledger. Before selecting another row by inspection, I re-decompiled every entry
at its recorded address from the real official binary and scored it with the
unmodified `TypeMatchMetric` cache version 4 with caching disabled. Parent
`58cf71d80b8a725e5aa64c4a3560e38168a33d32` already makes 11/29 perfect. The
current increment makes 13/29 perfect and leaves 16, not 28, open. The checked
ledger now records those exact 13 identities and rejects any status-count drift.

The next repeated owner was a call-contract transport seam. In diffutils
`lf_skip`, source parameter `arg0` is copied into `var2`; raw byte-offset uses
correctly keep `var2` machine-word typed, but a recovered `lf_refill(char *)`
contract is authoritative evidence that the exact source value came from a
pointer parameter. Pointer refinement previously inspected only direct `argN`
call operands, so it discarded that evidence. The repair walks prepared
definitions backward through pure copies to one unique source parameter. It
fails closed on arithmetic, calls, cycles, multiple definitions with different
origins, or an unsafe use of the source parameter. The intermediate value
therefore remains a word and the renderer emits the required explicit cast;
only the source parameter becomes a pointer.

The associated output seam was general opaque-tag spelling. DecBench ground
truth uses typedef names such as `line_filter *` and `mod *`, while Glaurung
rendered authoritative incomplete types as `struct line_filter *` and
`struct mod *`. Complete aggregates already used a self-contained typedef
alias. Explicitly tagged opaque prototype pointers now follow the same rule:
emit `typedef struct T T;` (or the union equivalent) and render `T *`. This is
prototype/type-environment behavior, not a function-name or benchmark patch.

TDD evidence was RED/GREEN at both owners:

- a recovered pointer contract transported through one exact copy initially
  left `arg0` untyped; it now recovers an eight-byte pointer while `var2` stays
  non-pointer, and a conflicting-origin control remains untyped;
- an opaque `struct record *` prototype initially emitted only
  `struct record; void consume(struct record * arg0)`; it now emits the
  standalone typedef and `void consume(record * arg0)`.

All 13 `ir::high_variables::tests`, the opaque-tag renderer regression, and the
29-row corpus contract pass. Real official output moves `lf_skip` from type
score `0.5` to `1.0` and `mod_free` from `0.0` to `1.0`. A fresh parent/current
address-scoped extraction then covered all 250 functions in 224 real binaries
with zero errors:

| TypeMatch result | parent `58cf71d` | current | Delta |
|---|---:|---:|---:|
| measured | 235 | 235 | 0 |
| perfect | 27 | 30 | +3 |
| mean | 0.32579001 | 0.35462582 | +0.02883581 |
| functions improved | — | 31 | +31 |
| functions regressed | — | 0 | 0 |

The third newly perfect full-corpus function is
`grep:O2-noinline:grep:finalize_input`; 36 artifacts change in total because the
opaque alias rule improves or normalizes other authoritative signatures too.
Safety was checked on that entire changed set, not only on the two cohort wins.
All 36 parent/current decompiled CFGs are topology-isomorphic (31 were directly
identical under Joern's node identities; five had different internal identities
but identical isomorphic graphs), so the official GED inputs and results cannot
change. Fresh no-cache ByteMatch evaluation also gives identical parent/current
scores for every changed function: the same 12 compile, the same 24 report the
same compilation failure, and neither score nor coverage regresses.

The mandatory heavy gate passed without a waiver after rebuilding the release
extension from this exact source. Full Rust tests and the 31-test x86 fixture
matrix passed. The architecture ratchet matched its baseline exactly: 1,757
behavioral passes, the same 43 known failures, 228 structural cases, zero lane
errors, and explicit AArch64, Thumb ARMv7, A32 `-marm`, i386, GCC 11 control,
and GCC 15 control coverage. Both legacy and curriculum executable matrices
passed, followed by no per-cell GED/type/byte regressions across all 56/56
DecBench cells.

## 06:35–08:00 — program-level DWARF type relationships

The next six verified-open cohort rows all had authoritative aggregate pointer
prototypes, but the public spelling was a typedef while the layout was keyed by
its private tag: `accDev_t -> struct accDev_s`, `busDevice_t -> struct
busDevice_s`, `List_t -> struct xLIST`, `ListItem_t -> struct xLIST_ITEM`,
`usbd_device -> struct _usbd_device`, and `wrkrInstanceData_t -> struct
wrkrInstanceData`. The renderer and DWARF field pass compared those spellings
directly. A valid typedef pointer was consequently discarded even though both
records already existed in the same binary.

`DwarfTypeEnv` is the first reusable program-level repair for that ownership
gap. It builds one conflict-aware index over typedef edges and struct, union,
and enum tags; follows alias chains with cycle detection; rejects multiple
indirection and malformed names; preserves pointer qualifiers; and supplies the
same resolved identity to signature rendering and field recovery. Opaque
layouts emit a real typedef forward declaration without inventing members.
Named enum typedefs use measured DWARF byte size and the presence of negative
enumerators to emit a compact ABI-equivalent alias. This lets rsyslog retain
`rsRetVal` without copying 313 enumerators into every function.

The RED tests exposed two additional composition seams. First,
`Record_t *arg0` copied into a recovered `char *` local produced an invalid
implicit conversion; assignment rendering now emits an explicit zero-cost cast
when two concrete pointer types differ. Second, the direct-callee prototype
path initially recovered `doTryResume` as returning `unsigned long` even after
the outer function resolved `rsRetVal`. The same type environment now feeds
prototype ABI hints at all four decompilation entry points, so the callee and
outer return value agree on a signed four-byte result.

An attempted broader scalar-typedef rollout was rejected by measurement. It
made `size_t` authoritative in `console_read`, and GCC changed the equivalent
loop test from the original `cmp r2,r3; blo` to `cmp r3,r2; bhi`, reducing the
official byte score by `0.01145`. Ordinary scalar aliases therefore remain
fail-closed until body values preserve their source typedef identity; enum and
aggregate relationships are enabled now because they pass the safety gates.

Fresh unmodified TypeMatch cache-version-4 scoring, with caching disabled,
moves the historical 29-row cohort from 13 to 20 perfect and leaves nine open.
All seven newly fixed rows are real-binary results: `wcomment`,
`icm20689SpiAccDetect`, `m25p16_enable`, `vListInitialise`,
`vListInitialiseItem`, `usbd_ep_nak_set`, and `beginTransaction`. The complete
250-function parent/current replay against exact parent `acc3e24` has zero
extraction errors:

| TypeMatch result | parent `acc3e24` | current | Delta |
|---|---:|---:|---:|
| measured | 235 | 235 | 0 |
| perfect | 30 | 41 | +11 |
| mean | 0.35462582 | 0.40518645 | +0.05056063 |
| functions improved | — | 32 | +32 |
| functions regressed | — | 0 | 0 |

Sixty-seven of 250 artifacts change. Joern parses every parent/current member
of that changed set and all 67 CFG pairs are topology-isomorphic, so GED does
not regress. Fresh no-cache ByteMatch produces identical scores and identical
compile/failure coverage for all 67. This includes `beginTransaction`, which
moves TypeMatch from zero to one while retaining byte score
`0.35714285714285715`.

The publication gate then passed every source and execution lane: full Rust
tests, the 31-test x86 fixture/structure matrix, the architecture ratchet at
its exact 1,757-pass/43-known-failure baseline, and both legacy and curriculum
executable matrices. The first four-worker metric invocation exposed a
`pyjoern` first-use extraction race: four workers concurrently unzipped the
same bundled CLI, so the four `arith` cells errored while the other 52 scored.
That partial result was not credited. After verifying the CLI installation, a
fresh four-worker invocation scored all cells and reported no per-cell GED,
TypeMatch, or ByteMatch regressions across 56/56 cells.

The repository-wide Python run then completed with five failures. One was a
lane-owned brittle ARM32 assertion that assumed a
signature was always the second output line; a correct typedef declaration now
precedes aggregate signatures. The test now locates both affected signatures
by function name and passes. The other four are the pre-existing suspicious
cross-sample failures, unrelated to decompilation or this change.

## 08:00–13:20 — close the 29-row type cohort and audit score side effects

The remaining nine rows were not nine isolated spelling bugs. They shared four
missing semantic owners: source-local DWARF contracts, lifetime-aware value
identity, elimination of unobserved promoted-object stores, and pointer
arithmetic expressed in source element units. The repair therefore imports
DWARF local names, types, byte extents, register locations, and location ranges;
keeps values from disjoint source lifetimes out of the same phi/value-number
class; permits declaration-only optimized constants; and removes stores only
when the promoted object has no read, escape, or other observer. Exact-address
DecBench requests also bypass the section-name filter because real functions
may live in compiler-generated executable sections outside `.text`.

Two rendering safety seams were exposed by RED tests. Native pointer arithmetic
must convert the machine byte displacement into a C element displacement, but
only when the authoritative scalar pointee width equals the recovered width;
opaque aggregate pointers retain explicit byte arithmetic. Separately, a local
whose name equals an aggregate typedef, such as `struct passwd *passwd`, must
use the tagged spelling so the declaration does not hide its own type. Both
rules are centralized and fail closed. A deliberately broad scalar-typedef and
array rollout was rejected after it caused 23 TypeMatch regressions. A broad
pointer-cast experiment was also rejected after it introduced compilation
regressions.

Fresh cache-version-15 evaluation on the 29 checked real binaries scores all 29:
27 are perfect and two emit the exact expected declarations,
`COLUMN *p;` and `discover_class_node *node;`. TypeMatch v5 scores those two as
`0.8` and `0.5` because its declaration parser recognizes selected typedef
forms but not these ordinary typedef pointers. The corpus ledger therefore
records 29 Glaurung-side resolutions, 27 verified perfect rows, and two metric
false negatives rather than leaving product defects open.

The full 250-function replay uses 224 freshly processed binaries with Glaurung
caching disabled and no extraction errors. Against accepted parent `acc3e24`,
common scored functions have 123 improvements and zero regressions:

| TypeMatch result | parent `acc3e24` | current | Delta |
|---|---:|---:|---:|
| measured | 235 | 233 | -2 |
| perfect | 41 | 68 | +27 |
| mean | 0.40518645 | 0.56153998 | +0.15635353 |

The different measured denominators are explicit: two x0r address/name
requests return no Glaurung artifact, while 17 total rows remain unscored due to
available DWARF/metric input. The improvement/regression count is computed only
over keys scored on both revisions.

ByteMatch was rerun fresh because source-equivalent type repairs can still alter
compiler shape. Parent scores 250 rows, 10 perfect, mean `0.16168974`; current
scores 248 rows, 11 perfect, mean `0.19063337`. On 248 common rows, 33 improve
and nine regress. This audit found and repaired two genuine emission defects:
native pointer scaling had rendered an eight-byte displacement as eight
elements in `env_free`, and a typedef/local collision made `user_name`
uncompilable. The remaining nine changes are bounded compiler-shape tradeoffs,
not silently called neutral; their TypeMatch generally improves substantially
(for example `gpio_toggle` `0.667→1.0`, `write_power_mode` `0.2→1.0`, and
`dwc_poll` `0.143→1.0`).

The final CFG audit parses all 175 parent/current pairs for which both artifacts
contain code. A bounded directed structural fingerprint is identical for 148;
contracting straight-line declaration blocks raises that to 168. Seven
functions have real control-skeleton changes from the lifetime-aware SSA/value
repair: `diversion_add`, `grep::main`, `revoked_certs_generate`,
`oslib_test_009_004_execute`, `mspProcessInCommand`, `ssh_agent_sign`, and
`USB_OTG_FlushRxFifo`. They are retained as behavior-changing canaries rather
than mislabeled GED-neutral. Unbounded exact graph isomorphism was rejected as
a gate after it stalled on a large symmetric graph.

Finally, the first cohesive DWARF-contract owner was extracted from
`python_bindings/ir.rs` into a 449-line module, reducing the binding owner to
3,656 lines without creating a forwarding-only fragment. Full Rust testing with
the Python extension enabled passes 2,008 library tests plus every integration
and documentation test. Focused Python formatting/lint and the owned DecBench
tests pass. The repository-wide Python run reports 2,864 passed, 44 skipped,
and 12 failures. Eight decompiler failures were obsolete shape assertions: they
required anonymous `local_x` names or one transient temporary even though the
new output recovered authoritative source names and still reached the existing
compile/execute oracle. Those eight tests now assert the source-level semantic
invariant and pass in a focused rerun. The four remaining failures are the known
cross-architecture `suspicious_win` sample-content failures and do not execute
the changed decompiler path. Repository-wide `ty check` remains a baseline-red
gate with 2,064 diagnostics. Strict Clippy is also baseline-red (193 warnings
under `-D warnings`); `--all-features` additionally requires the external pinned
Bitwuzla library. These failures are reported rather than recast as green.

## 13:20–16:20 — reusable session and definition-safe emission repairs

The next Phase 1 increment adds an actual `ProgramSession`, rather than another
temporary byte-oriented entry point. One immutable `ProgramImage` now owns a
bounded, exact-key discovery cache. Its key includes every discovery budget and
the normalized, sorted function seed set, and its 256-entry LRU exposes hits,
misses, entries, and evictions. The Python `DecompilerSession` uses that same
owner and adds an exact rendered-artifact cache keyed by address, limits, type
mode, style, and function budget. Requests with pass-health, pipeline-profile,
definition-verification, or other diagnostic modes bypass the render cache so a
cached string cannot suppress requested evidence. Module-level compatibility
calls still construct a temporary session.

Real compiled ELF tests prove that exact repeated queries are output-identical
to the compatibility API, that style and budget changes do not collide, that
invalid images fail during session construction, and that clearing caches resets
both artifacts and counters. On the checked-in O0 hello binary, three standalone
queries had a 13.438 ms median, the first session query took 12.884 ms, and ten
exact cache hits had a 0.001136 ms median. All fourteen outputs had the same
SHA-256 digest. This 11,826.9x exact-query result measures the rendered-artifact
cache, not general warm analysis; broader discovery and fact caching remains
open and must not inherit this number.

The same batch repaired four correctness owners found by executing real
DecBench outputs rather than by optimizing metrics:

1. Parameter-home coalescing now asks a symmetric structured reaching-definition
   query before treating a promoted source object and its incoming argument as
   interchangeable. A mutation remains distinct when the entry value is still
   live, while an exact `home = arg` initializer is not misclassified as both a
   write and an independent read in goto-heavy bodies.
2. Copy propagation preserves an indirect store's lvalue category. Replacing a
   pointer scratch with the bare name of a promoted object can no longer turn
   `*pointer = value` into `local = value`; this was the direct cause of the
   AArch64 and A32 `heap_pop` buffer corruptions.
3. Source-local DWARF identities are protected through preparation, selected
   only on a unique evidence winner, and declared in semantic first-use order
   rather than renamed lexical order. Equal location evidence remains
   declaration-only instead of arbitrarily rewriting one machine value.
4. Loop recovery has a narrow typed owner for carried-value latches and
   source-variable updates. It requires one dominating scratch definition,
   compatible proven widths, no old-carrier read after the definition, no later
   scratch use, straight-line update statements, and no unsafe cross-region
   transfer. This restores source `i++` without a renderer heuristic.

The first loop-update implementation exposed an official regression in
`arrays:gcc:O2`: ByteMatch fell from 0.49 to 0.20 because a wide scratch remained
as the rendered loop variable. The typed carrier proof removes that scratch and
the fresh cell is back to the accepted triple: GED 8.33, TypeMatch 0.93,
ByteMatch 0.49. The historical `linkedlist:clang:O0` concern was also rerun in
the complete matrix and now scores GED 0.0, TypeMatch 1.0, ByteMatch 0.31; it is
no longer the unexplained 0.10 candidate, but it remains below the earlier 0.47
observation and should stay a compiler-shape canary.

The final unstructured-reaching repair was verified through every required
local gate. Rust reports 2,037/2,037 library tests. The focused reusable-session
and real structural fixtures pass. The complete x86 fixture/structural matrix,
the legacy executable matrix, and all 64 curriculum behavior lanes pass. The
cross-architecture matrix has zero new failures and one independently reproduced
improvement: parent `30c9951` fails `18_binary_heap:i386:O0:heap_push`, while the
candidate passes it under the same GCC 15.2/qemu-i386 lane. The accepted ratchet
therefore advances from 1,757 pass / 43 known failures to 1,758 / 42; AArch64 is
328/328, and both AArch64 and A32 `heap_pop` pass their focused real executions.

Finally, a fresh isolated four-worker DecBench run recomputed GED, TypeMatch,
and ByteMatch for every official cell. It completed 56/56 with no per-cell
regression. This is publication evidence for the current batch, not evidence
that the remaining optimized GED cliffs or unscored TypeMatch cells are solved.

The repository-wide Python suite reaches 100% with exactly four failures, all
in `test_suspicious_symbols_if_present` for the known cross-compiled
`suspicious_win` sample-content mismatch; no changed decompiler/session test
fails. Repository-wide `ty check python/` remains baseline-red with 1,939
diagnostics, and the pre-existing monolithic `__init__.pyi` Ruff baseline has
247 modernization findings. The new session test passes focused Ruff and ty,
Rust formatting is clean, and `git diff --check` passes. These baseline failures
remain explicit rather than being waived as a green repository-wide gate.
The loop proof's 504-line RED/negative-control suite lives in a separate child
test module, leaving the production owner at 803 lines instead of adding another
source file above the roadmap's 1,000-line threshold.

## 16:20–20:25 — stripped-submission truth and ARM value-lifetime repair

The next run deliberately discarded every prior score claim and started from the
external evaluation kit again. This exposed an important evidence boundary that
the later diary entries had not stated strongly enough: all 224 kit binaries are
stripped, while the local score tree's compiler outputs retain DWARF so the
evaluator can construct ground truth. The high TypeMatch results obtained by
decompiling those debug-bearing compiler outputs measure a useful
debug-assisted product mode, but they are not a prediction of the external
submission. The stripped-kit replay below is the authoritative scoreboard
candidate. In particular, the earlier `0.56153998` TypeMatch mean must not be
quoted as external-submission performance.

Six related correctness repairs were developed RED/GREEN/REFACTOR against exact
values and then exercised on the real stripped binaries:

1. ARM r0–r3 raw-register pointer evidence no longer flows backward into a
   different live-in lifetime. Exact SSA address evidence still recovers real
   pointer parameters, while `console_getc(int wait)` remains scalar.
2. A uniquely caller-supplied spill/reload is distinguished from a local index
   reload when both feed pointer arithmetic. This recovers the buffer in
   `console_read` without declaring every frame reload a pointer.
3. Conflicting byte and word accesses on one exact pointer value preserve an
   honest opaque `void *` contract rather than choosing an arbitrary element
   width. The small TypeMatch tradeoff on `hard_fault_handler` remains explicit:
   `0.31818→0.27273` versus the preceding candidate, but it is still above the
   accepted parent (`0.22727`) and avoids inventing a concrete pointee type.
4. Pre-folded ARM epilogue frame-pointer arithmetic is excluded from indexed
   stack-object seeding. The narrow rule prevents a machine frame from becoming
   a giant source byte array; a broader frame-pointer exclusion was rejected
   after a real armv7 regression.
5. High-variable propagation now consumes the return type already attached to a
   recovered program-local call site. A pointer returned by a local callee
   therefore stays a pointer through exact copies instead of reverting to
   `long`.
6. A recovered concrete pointer parameter is reasserted at the call boundary
   when the underlying expression has only byte-object or machine-word
   representation. Opaque `void *` parameters remain unforced. This repaired
   the real Betaflight `mspProcessInCommand` failure, including the
   `vtxCommonGetStatus(char *, int *)` stack-address argument.

The first boundary-cast implementation cast every unknown expression, including
calls whose declared parameter was itself `void *`; full Rust tests rejected it
because it overrode the intended opaque-pointer behavior. The retained rule is
parameter-aware. Likewise, a global ARM pointer filter and the broad frame skip
were rejected rather than credited.

The exact code revision is `06b2e614a6b84e96e594daf23933376078fe1092`.
The fresh package covers 224/224 binaries and 250/250 functions with zero
extraction failures. Its SHA-256 is
`754db0bc3d7217c5dce7111db13fb0d20020c80905e76893415c2c7ca65d2bec`;
the raw diagnostic ledger is
`d00a715e4f3a9c34d57e628e56e44c39021ef7cdfb93a1f36e9b83e4b43527bf`.
The run used eight workers while other verification was active, so its 85.58 s
wall time is completeness evidence, not a replacement performance baseline.

Fresh corrected scoring gives:

| Metric | Coverage | Perfect | Mean | Median | Zero |
|---|---:|---:|---:|---:|---:|
| GED, published source CFGs | 239 / 250 | 60 | 32.3640 | 10.0 | 60 |
| TypeMatch, stripped submission | 235 / 250 | 15 | 0.213917 | 0.083333 | 100 |
| ByteMatch, PR #61 path | 250 / 250 | 7 | 0.235539 | 0.216542 | 55 |
| union perfect | 250 / 250 | 71 | — | — | — |

Against accepted parent `ae88988`, TypeMatch improves 13 common functions,
regresses none, adds one perfect, and moves the mean from `0.185213` to
`0.213917`. Against the immediately preceding ARM candidate it gives back
`0.04545` on only `hard_fault_handler`, without losing a perfect. ByteMatch is
the larger reliability result: versus that preceding candidate, compilable
coverage rises from 210 to 242, the mean from `0.202560` to `0.235539`, and the
median from `0.154243` to `0.216542`; 28 scores improve, none regress, and all
seven perfects remain. The 32 newly compilable functions include
`mspProcessInCommand`, `copy_reg`, `yyparse`, `statdb_write`, and
`ssh_agent_sign`.

The honest union is therefore 71/250 (`28.4%`). Joining those exact keys to the
pinned nine-decompiler public snapshot
`ed005ed3b2ec0d42bb607165d39cbabf59d8d8b54fa774fb43114c00c5320bf6`
projects Glaurung sixth: below Kuna's 29.1% and above Binary Ninja's 28.1%.
This remains a projection until DecBench accepts and publishes the submission.
None of Glaurung's 71 union-perfect functions is unique versus that snapshot,
and the GED mean remains far from competitive, so the rank is not a claim of
structural parity.

Verification is separated by gate rather than collapsed into “green.” Default
Rust testing passes 1,951 library tests plus every integration target; the
architecture ratchet remains 1,758 pass / 42 known fail / 228 structural / zero
lane errors / six declared unsupported. The full Python suite reaches 100% with
only the four known `suspicious_win` cross-sample content failures. Rust format
and `git diff --check` pass. Repository-wide Ruff and `ty` remain baseline-red
on pre-existing Python debt and were not rewritten as success. Earlier build
attempts that exhausted the disk quota were discarded and not credited; the
successful Rust run used a clean, reproducible no-debuginfo target.

## 20:30–21:20 — Thumb leaf-frame ownership and fresh stripped replay

The distance-one TypeMatch census was recomputed from the metric checkpoints,
not inferred from aggregate scores. Two repeated near misses (`try_help` at O0
and O2) require caller-site program evidence because the callee only forwards
its first argument through a variadic call. `balance` requires an aggregate
environment to recover `COLUMN *` rather than merely `int *`. Those rows are
therefore evidence for the program-level type and aggregate epics, not safe
intraprocedural width tweaks.

The nearest ARM row exposed a separate real correctness defect. GCC's Thumb O0
leaf prologue may save only `r7`, without saving `lr`. `recognise_arm32_frame`
therefore declined the prologue, stack promotion named the save at
entry-SP-minus-four `local_4`, and the restore used the separate `stack_top`
coordinate. The dead-spill owner could not pair those names and emitted an
uninitialized source assignment such as `local_4 = var0`.

The retained repair teaches callee-saved-spill pruning that an unread promoted
`local_*` whose exact source is an ARM callee-saved core register (`r4` through
`r11`, including `fp`) is machine-frame state. It deliberately does not remove
an otherwise identical `local_4 = r0`. RED tests covered both cases before the
implementation, and a real `arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -O0`
integration fixture reproduces the leaf prologue and verifies that the real
signed-byte source local remains while the fake frame local disappears.

A new external-kit replay again started from an empty `results/` directory and
returned 250/250 functions across 224/224 binaries with zero extraction
failures. The package SHA-256 is
`f1a6d649af6a7bbfd74cc00e8b8c8778f254a85811c499522928ffe202bad4c2`;
the diagnostic ledger SHA-256 is
`3ac506710395fe3e15059583b8c3f665121b420943dafad769867e3d0e29e89f`.
Thirty-four stripped ARM outputs changed. Fresh ingestion used a new
`glaurung-leaf-frame` column in an independent score-tree copy, so neither the
old Glaurung checkpoint values nor the old generated C could satisfy the run.

| Metric | Previous | Leaf-frame candidate | Delta |
|---|---:|---:|---:|
| TypeMatch coverage | 235 / 250 | 235 / 250 | 0 |
| TypeMatch perfect / mean / median | 15 / 0.213917 / 0.083333 | 15 / 0.212873 / 0.083333 | 0 / -0.001044 / 0 |
| ByteMatch coverage | 250 / 250 | 250 / 250 | 0 |
| ByteMatch perfect / mean / median | 7 / 0.235539 / 0.216542 | 8 / 0.247425 / 0.219375 | +1 / +0.011885 / +0.002833 |
| recompiles / zero ByteMatch rows | 242 / 55 | 242 / 53 | 0 / -2 |

ByteMatch changes on 26 rows: 21 improve and five regress. The new exact byte
match is FreeRTOS `vApplicationGetIdleTaskMemory`; it was already GED-perfect,
so the honest union remains 71/250 (`28.4%`) and the projected placement remains
sixth. TypeMatch gives back `0.20` on
`libopencm3:usb_control_request_dispatch` and `0.04545` on RIOT-OS
`hard_fault_handler`; both losses arise because a machine-frame declaration no
longer accidentally participates in source-variable alignment, and neither
loses a perfect. The evaluator's stack-shift calibration also continues to
align `console_getc`'s true byte local against the already-position-matched
argument, leaving its TypeMatch at `0.5` despite the emitted-C correction.

The materialized scoring tree contains no preprocessed `.i`/`.ii` inputs, so
the fresh inline evaluator correctly produced no GED column. The last accepted
published-source CFG ledger remains 239 measured, 60 perfect, mean `32.3640`,
median `10.0`; it is retained as prior evidence rather than relabeled as a fresh
GED run. Full Rust verification passes 1,953 library tests plus every integration
target, and the six-lane architecture ratchet still matches exactly at 1,758
pass / 42 known fail / 228 structural / zero lane errors / six declared
unsupported. Rust and Python formatting, `git diff --check`, the focused real
Thumb test, and targeted Ruff are clean. Targeted `ty` remains baseline-red with
30 existing diagnostics in `test_cli_decompile.py`; none points into the new
fixture.

## 21:20–22:50 — exact SysV narrow parameter homes and a new union win

The next distance-one TypeMatch row was `findutils:O0:find:prec_name`. Its first
wrong stage was not rendering: GCC receives a source `short` in `edi`, masks the
low 16 bits through `eax`, and stores `ax` into the frame home. The existing
spill owner followed exact copies only, so it could not connect that home back
to the version-zero `rdi` live-in and left the declaration at ABI width.

The retained rule records mask/truncation edges as provenance without unifying
their wide and narrow values in the ordinary type lattice. A frame home becomes
strong declaration evidence only when all of these conditions hold:

- the chain starts in block zero and reaches an exact version-zero SysV integer
  argument register;
- it contains an explicit `0xff`/`0xffff` mask or truncation;
- the same live-in has no ordinary full-width spill; and
- there is exactly one distinct narrow destination.

This is intentionally narrower than declaring every word store a `short`.
Four RED Rust cases cover a signed word parameter, an unsigned word parameter,
an `int` parameter copied into a local `short`, and an ambiguous direct narrow
spill. A real stripped host-GCC integration fixture then compiles and strips a
source `short` function before decompiling it by address; the recovered
signature is `int sub_401000(short arg0)`. Sign extension wins when the same
proven home also has zero-extension transport evidence, while a lone zero
extension remains unsigned.

A new external replay started from an empty result directory and extracted all
250 functions from all 224 stripped binaries with zero extraction failures.
The result manifest SHA-256 is
`5d5e1fc27f3c68fd88e372d5f999a321d81dabb48ead2d02b36f760dcfbacde3`;
the packaged `results.zip` SHA-256 is
`cf30fa213e8e5cca54cadb23172e1f4fa77bbafc71c01c1631e9c420046808d0`,
and the diagnostic ledger SHA-256 is
`9322cb5352e45446fe15d16f0a0e691db5ca1a2d9c86134c3a997d05a75d7429`.
Only seven emitted functions differ from the leaf-frame candidate. Each was
rescored with caches disabled and all seven still compile. `prec_name` improves
from TypeMatch `0.5` to `1.0` and ByteMatch `0.21875` to
`0.288135593220339`; the other six retain their prior TypeMatch and ByteMatch
scores. There are therefore zero affected-row metric regressions.

Fresh aggregate scoring of the new submission column gives:

| Metric | Coverage | Perfect | Mean | Median | Zero |
|---|---:|---:|---:|---:|---:|
| GED, prior published-source CFG ledger | 239 / 250 | 60 | 32.364017 | 10.0 | 60 |
| TypeMatch, fresh stripped submission | 235 / 250 | 16 | 0.215000 | 0.083333 | 100 |
| ByteMatch, fresh PR #61 path | 250 / 250 | 8 | 0.247702 | 0.220977 | 53 |
| union perfect | 250 / 250 | 72 | — | — | — |

The union increases because `prec_name` was not previously perfect in GED or
ByteMatch. The honest external projection is now 72/250 (`28.8%`), still sixth
and immediately below Kuna's 29.1% in the pinned public snapshot. This is a
near-neighbor placement, not a claim that the remaining GED distance is small.
An exact key join independently yields 60 GED, 16 TypeMatch, and eight
ByteMatch perfects: GED/TypeMatch overlap on six keys, GED/ByteMatch on five,
TypeMatch/ByteMatch on one, and no key is perfect in all three metrics.
Fresh GED is still unavailable because this materialized tree has no `.i`/`.ii`
sources, so the table labels that column as prior rather than silently reusing
it as fresh evidence.

Verification remains split by scope. Focused type recovery passes 62 tests, the
full Rust run passes 1,957 library tests plus every integration target, the real
CLI file passes all 30 tests, and the architecture ratchet remains exactly
1,758 pass / 42 known fail / 228 structural / zero lane errors / six declared
unsupported. The full Python suite reaches 100% with only the same four
cross-sample `suspicious_win` content failures. Rust format, Python format,
targeted Ruff, and `git diff --check` pass. Targeted `ty` reports the same 30
pre-existing diagnostics in `test_cli_decompile.py`, with none on the new test.
Both executable behavior matrices pass all 56 legacy and 64 curriculum cells,
and a fresh four-worker DecBench run reports no per-cell GED, TypeMatch, or
ByteMatch regression across 56/56 cells. The final release-build extraction
takes 67.36 s at eight workers; its per-binary median is 2.155 s, mean 2.389 s,
and maximum 3.739 s. Those timings establish the current artifact's performance
and completeness, but are not attributed solely to this type-recovery change.

## 22:50–00:10 — program-level callback contracts cross the pinned threshold

The next distance-one row, `diffutils:O2-noinline:diff:stophandler`, proved the
limit of function-local prototype recovery. Its source contract is
`void stophandler(int sig)`, but optimization removes every use of `sig`; the
callee body therefore contains no honest evidence from which to reconstruct the
parameter. The surviving evidence is in another function: `stophandler` is
stored in `struct sigaction.sa_handler` and that object is passed to
`sigaction`.

The retained repair adds an immutable, session-cached `ProgramEnvironment` for
cross-function semantic facts. A bounded abstract interpreter follows concrete
stack-object offsets, scalar flags, and code-pointer sets through the function
that registers a callback. A raw direct-call/code-reference scan is only a
prefilter: a fact is emitted only after the registration site is assigned to an
exact `.eh_frame` owner, that owner is lifted, and its LLIR proves the matching
data flow. Ordinary calls clear the target ABI's centralized caller-saved
register set, joins retain only agreeing facts, code-target unions are capped,
and conflicting contracts are discarded. The `sigaction` rule additionally
requires concrete flags proving `SA_SIGINFO` clear; three-argument handlers are
left unknown rather than misdeclared as one-argument callbacks. `signal` uses
the same evidence path. The byte scanners now translate each contiguous code
range once instead of performing a VA lookup for every byte.

The real RED fixture compiles three host-GCC `-O2` callbacks, strips the binary,
and decompiles all three together. The registered one-argument handler now
renders `int arg0`; a merely address-taken `void` callback remains `void`; and a
registered `SA_SIGINFO` callback remains `void` until a sound three-argument
contract is implemented. A separate unit regression requires both arms of a
conditional value to agree before the program analysis retains a fact.

An eager prototype lifted every registration owner in every query and was
rejected after a full replay raised median/mean/max extraction time to
2.602/2.887/19.235 seconds. The retained demand-driven design intersects a
registration owner with an owner that references one of the requested callback
addresses before lifting it. A fresh optimized replay from an empty result
directory emits all 250 functions across all 224 binaries with zero failures.
Exactly one generated C file changes, and its only semantic diff is:

```c
-void sub_d620(void) {
+void sub_d620(int arg0) {
```

The package SHA-256 is
`d259581d5e1c021e45a62a93f84b9687666b548ce5d3579c5401c200718fc662`,
the diagnostic ledger is
`604e82530ad57a70b3675804f54905f83a868faf5034222aeac9a3b693f33b61`,
and the result manifest is
`78c5ed54905db1822cf9da4f2fbf83f72a8b7f24e8799541f14c5ff4cfcf0cbf`.
The eight-worker run took 69.89 seconds while the full Python suite was also
active; per-binary median/mean/max were 2.263/2.479/4.170 seconds. Mean is 3.8%
above the prior 2.389-second release replay and remains inside the Phase 1 cold
guardrail; the overlapping workload makes this conservative performance
evidence rather than a clean microbenchmark.

With `DECBENCH_NO_CACHE=1`, TypeMatch v5 freshly scores `stophandler` at exactly
`1.0` (`tp=1`, `fp=0`, `fn=0`). ByteMatch v6 remains `0.7777778`, and its CFG
body is unchanged. Because this row was not already perfect under GED or
ByteMatch, the exact union advances 72→73/250 (`28.8%→29.2%`). Against the
pinned public snapshot this crosses Kuna's 29.1% by 0.1 percentage point. It is
still a projection, not a live DecBench leaderboard claim, and fresh GED remains
unavailable until the evaluation tree contains preprocessed sources.

Final verification passes 2,052 Rust library tests plus every integration
target, all 31 CLI/decompiler tests, the exact six-lane architecture ratchet
(1,758 pass / 42 known fail / 228 structural / zero lane errors), all 56 legacy
and 64 curriculum behavior cells, and the fresh 56/56-cell metric ratchet with
no GED, TypeMatch, or ByteMatch regression. The full Python suite has only the
four known cross-sample `suspicious_win` content failures after its one
load-induced Windows truncation passes alone. Rust/Python formatting, targeted
Ruff, and `git diff --check` pass. Targeted `ty` remains at the exact 30 existing
diagnostics in `test_cli_decompile.py`, with none on the new fixture; global
Ruff and `ty` remain baseline-red repository debt rather than being mislabeled
as green.

## 00:10–01:15 — conflict-aware nominal libc pointer recovery

The next TypeMatch defect, `bash:O0:mksyntax:wcomment`, exposed a distinction
that the existing call-contract catalog intentionally erased. `fputc` accepts
`FILE *`, but its standalone boundary type is conservatively rendered as
`void *` because the output previously had no owner for an opaque `FILE`
declaration. Consequently, exact repeated calls proved the parameter's nominal
contract while the recovered function signature could express only its machine
pointer category.

The retained repair keeps those layers separate. The catalog still supplies
`void *` at an isolated call boundary, while a final prototype refinement walks
direct call operands and records catalog-owned opaque pointer typedefs for exact
`argN` values. A parameter is refined only when every canonical observation
agrees. Conflicting callees, derived values, arbitrary identifier spellings,
and non-opaque catalog types fail closed. The renderer accepts the resulting
nominal pointer and emits one standalone forward declaration such as
`typedef struct __glaurung_opaque_FILE FILE;`.

An earlier byte-use experiment that inferred `char *` merely because a pointer
fed byte loads was rejected. That evidence cannot distinguish a source string
from a byte view into a wider object and would have collapsed machine access
width into source identity. The retained implementation instead uses the
existing call-contract owner and carries only named evidence that the catalog
actually knows. RED/GREEN tests cover agreement, conflict, and rendering, while
a direct predicate test covers builtin, struct, and arbitrary-token exclusions.
A real integration fixture compiles a GCC O0 ELF with a
`FILE *` parameter, strips its debug information, decompiles it by address,
then recompiles and executes the result against the original output.

The first full replay caught a separate integration mistake before acceptance:
constructing a replacement render prototype also replaced the established
return-type owner, changing unrelated signatures to `long`. The final pipeline
starts from the normal inferred return type and refines only parameter slots.
A new release replay from an empty results directory then emitted all 250
functions from all 224 binaries with zero failures. Exactly three outputs
changed:

| Function | Previous TypeMatch | Candidate TypeMatch | ByteMatch before/after |
|---|---:|---:|---:|
| `e2fsprogs:O0:e2fsck:print_problem` | 0.5 | 0.666667 | 0.287009 / 0.287009 |
| `iproute2:O0:ip:print_rta_ifidx` | 0.25 | 0.5 | 0.253731 / 0.253731 |
| `bash:O0:mksyntax:wcomment` | 0.5 | 1.0 | 0.288889 / 0.288889 |

All affected scores were recomputed with metric caches disabled, and all three
generated files compile. The fresh stripped TypeMatch projection is 18 perfect,
mean `0.22315622`, median `0.08333333`, and 99 zero rows over 235 measured
functions. This is meaningful movement toward the 0.231 type blocker, but it
does **not** add a union-perfect row: `wcomment` and `print_problem` were already
GED-perfect, while `print_rta_ifidx` remains imperfect. The honest union stays
73/250 (`29.2%`). The next placement-oriented repair must therefore target a
row such as `balance` or `try_help` that is not already covered by another
perfect metric.

The exact candidate package validates 224/224 binaries and 250/250 functions.
Its `results.zip` SHA-256 is
`6f331746e8ac1bbe5b30ec71025ae68923a41ff30947afe4537de7a95c5355dd`,
the result-manifest SHA-256 is
`3e9af5fb1b0965ca0f5f7d8f53c1c926183cf3f18ffe5761e0144b50835c46e3`,
and the diagnostics SHA-256 is
`3c3ea7701ea4563b4a02824fdcba8981eaa3c68ff4da5a2410697a1f07060e4f`.
The final post-fix release extraction took 72.83 seconds at eight workers;
per-binary median/mean/maximum were 2.388/2.580/3.880 seconds. Mean is 4.1%
above the callback-contract candidate and remains within the Phase 1 5% cold
guardrail. These whole-run numbers bound the candidate but are not attributed
to a three-output rendering change without a profile.

The first full Python gate then found a boundary error that the stripped score
sample did not exercise. Because `void *` is itself present in the catalog and
its standalone spelling is also `void *`, the opaque-name predicate initially
accepted `void` and emitted the invalid declaration
`typedef struct __glaurung_opaque_void void;` for three debug-assisted
recompilation fixtures. The repair explicitly excludes `void` and every builtin
scalar before catalog ownership is considered. A direct `void *` negative test
now guards that distinction, and the atomic compare-exchange, indirect-call,
known-`memcpy`, and stripped-`FILE *` recompilation tests all pass together.
This is why the full product suite remains a required acceptance gate even when
all changed official-score rows compile.

After that correction, a second clean release replay again emitted 250/250
functions across 224/224 binaries with zero failures. Every generated C file is
byte-identical to the already-scored pre-correction stripped candidate, proving
that excluding builtin `void` removes the debug-assisted regression without
changing any official submission row. Full verification then passes 1,963 Rust
library tests plus every integration target, all 56 legacy and 64 curriculum
behavior cells, the exact architecture ratchet (1,758 pass / 42 known fail /
228 structural / zero lane errors), and the fresh 56/56-cell metric ratchet
with no GED, TypeMatch, or ByteMatch regression. The full Python suite reports
2,879 passed and 44 skipped, with only the same four cross-sample
`suspicious_win` content failures. Rust/Python formatting, targeted Ruff, and
`git diff --check` pass. Targeted `ty` has exactly the four pre-existing
`pytest.mark` diagnostics in the round-trip file and none on the new test.

The checked output-canary baseline remains intentionally red rather than being
silently refreshed: it still expects older outputs for `console_getc`,
`copy_reg`, `linkedlist:clang:O0`, `statdb_write`, and `yyparse`. The fresh
official replay shows that this increment changes only the three named
`FILE *` rows; updating those older canaries remains separate Phase 0
publication debt.

## 01:15–04:17 — literal-format contracts for stripped wrappers

The placement-oriented follow-up examined `balance` and `try_help`, the two
named rows nearest a new exact TypeMatch win. `balance` would require recovering
a source aggregate identity that the stripped binary does not preserve. Naming
that struct from the expected source would be benchmark-specific guessing, so
that path was rejected. `try_help` instead has real program-level evidence: its
second parameter is forwarded through the variadic tail of `error`, and direct
callers supply literal translated `printf` formats that state the operand type.

The retained implementation adds parameter-only facts to the existing
`ProgramEnvironment`; it does not invent a second signature pipeline or force a
return type. A bounded abstract interpretation tracks entry parameters, literal
data addresses, proven zero values, and message identity through `gettext` and
`dcgettext`. It first proves which wrapper parameter reaches `error`'s format
slot and which parameters reach its variadic slots, then inspects exact lifted
direct callers. Every verified non-null format must be a supported literal and
all observed conversion types must agree. A null literal is neutral; a dynamic,
positional, dynamic-width, wide-string, invalid-length, unsupported, or
contradictory format discards the fact. This is deliberately direct-call
evidence: indirect or otherwise unobserved callers do not become positive
evidence.

The real RED fixture compiles and fully strips an optimized host-GCC binary.
The positive wrapper has two `%s`/null callers and now recovers
`char * arg1`. Three near misses remain unknown: a null/non-converting-only
wrapper, a `%s` versus `%ld` conflict, and a known literal plus a runtime format.
A parser unit test also pins positional, dynamic-width, wide-string, and invalid
float-length rejection. Implementing the data flow exposed two general abstract
execution gaps: self-XOR zeroing and zero-preserving extend/truncate operations
now retain proven zero rather than turning it into an unknown argument.

The first green implementation pushed the callback environment owner above
1,200 lines. Format-specific discovery and parsing were therefore extracted
into `program/format_environment.rs`; `program/environment.rs` is 902 lines and
the new cohesive owner is 376 lines after formatting. A cheap import prefilter
also avoids lifting targets in binaries that cannot contain this contract.
Shared state transfer, call-site discovery, and prototype facts remain owned by
the program environment rather than duplicated.

Fresh cache-disabled scoring with the current DecBench checkout's TypeMatch
cache schema v4 gives both affected official rows exactly `1.0` (`tp=2`,
`fp=0`, `fn=0`): `try_help` in `bin_105` at O0 and `bin_148` at O2. Each pinned
row was previously `0.5`; both had GED `33` and non-perfect ByteMatch
(`0.37778` and `0.58065`). Subject to the final full-package differential, the
union therefore projects 73→75/250 (`29.2%→30.0%`), TypeMatch perfects 18→20,
and TypeMatch mean `0.22315622→0.22741154` over the same 235-row denominator.
The older external notes call the compatible no-cache scorer v5; this record
uses the version label reported by the current unmodified evaluator rather than
silently merging labels.

The final fresh submission replay emitted 250/250 functions across all 224/224
binaries with zero extraction failures. Compared with the accepted `FILE *`
candidate, exactly `bin_105.c` and `bin_148.c` change; both diffs are solely the
second parameter changing from `long` to `char *`. The validated package
SHA-256 is
`072edf1a4ca7b460ec882f9c29efc067d6f1fb47d787e1bfeb9fd4e2d650643f`,
the result-manifest SHA-256 is
`0b215ac52162da6cb6c6a510feeb5afc23e08969cd45876f68125ff020730e2f`,
and the diagnostic-ledger SHA-256 is
`55e6824f956022f0c7f547fdda0050967314806641794609aab01184306e5be0`.
The exact differential converts the projection into a 75/250 (`30.0%`) union
result on the pinned score snapshot.

The eight-worker extraction measured per-binary median/mean/maximum of
2.547/2.855/14.058 seconds. This is not accepted as a clean Phase 1 performance
measurement: unrelated Axeyum fuzz jobs consumed 200–600% CPU throughout, three
older analysis processes each consumed another core, and host load remained
roughly 9–14. A first noisy run before restoring the no-sink early exit measured
2.631/2.960/20.195 seconds, so the retained fast path improved all three noisy
statistics, but neither run can establish the 5% guardrail against the prior
2.580-second mean. Output completeness and identity are valid; performance is
explicitly inconclusive pending an idle-host replay.

Final verification passes 1,964 Rust library tests plus every integration
target, the real stripped format/callback/`FILE *` focused tests, the exact
six-lane architecture ratchet (1,758 pass / 42 known fail / 228 structural /
zero lane errors), both 56-cell legacy and 64-cell curriculum behavior suites,
and the fresh 56/56-cell GED/TypeMatch/ByteMatch ratchet with no regression. The
full Python suite adds the new test and retains the four known cross-sample
`suspicious_win` content failures; under the heavily loaded host it also reports
the existing load-sensitive `win10-webservices.dll` discovery as truncated,
including on an immediate isolated rerun. This code path does not invoke the
new program environment, so it is recorded as an ambient gate failure rather
than mislabeled green or attributed to this increment. Rust/Python formatting,
targeted Ruff, and `git diff --check` pass. Targeted `ty` retains its existing
30 diagnostics and adds none on the new test.

## 04:17–08:01 — exact `.plt.got` tail calls and source/machine call effects

The next named correctness target was
`dpkg:O2:dpkg-statoverride:statdb_write` at `0x4800`. The source function is
`static void statdb_write(void)` and ends in `free(dbname)`, but Glaurung emitted
a scalar result and a dangling `goto L_35d0`. Disassembly identified the first
wrong stage: the terminal machine instruction is an unconditional jump to
`0x35d0 <free@plt>`, but that stub lives in `.plt.got`. Because the program
takes `free`'s address, its identity is carried by a `GLOB_DAT` relocation in
`.rela.dyn`, not an ordered `JUMP_SLOT` entry in `.rela.plt`; the existing ELF
PLT map therefore omitted it and CFG discovery retained the nonlocal transfer
as an ordinary branch.

The RED integration fixture compiles an optimized host-GCC program with
`-fcf-protection=full -Wl,-z,ibtplt`, takes `free`'s address to force the
`.plt.got` form, fully strips the binary, and decompiles a noinline tail wrapper.
It requires an exact `free@plt` mapping, a `void` one-pointer wrapper, a real
`free` call, no goto, and successful recompilation and execution of the emitted
C. Unit controls cover the ELF relocation/stub decoder, architecture-matched
PLT classification, declared-void ordinary calls, stale pre-tail-call result
register residue, fixed scalar versus variadic contracts, and ARM tail-call
classification.

The implementation advances shared owners rather than patching the function.
The ELF mapper now reads dynamic GOT relocations and decodes each x86-64
`.plt.got` RIP-relative jump, including CET `endbr64` and `bnd` prefixes, then
joins the stated slot to its exact symbol. CFG discovery treats unconditional
branches into `.plt`, `.plt.sec`, `.plt.got`, or `.iplt` as calls only when the
ELF object architecture matches the active decoder. Lifting represents a
CFG-proven terminal transfer as `Call + Return` with an explicit tail marker.
All Python decompile entry points use one helper that first adds conservative
ABI effects and then narrows resolved library calls from the symbol contract.

The call-effect split is the important definedness correction. A catalog
declaration of `void` does **not** delete the ABI return-register definition:
the callee still clobbers that machine register, and deleting the definition
would let stale pre-call state reach later reads. `CallEffects` now records the
machine result DEF separately from whether it can be a source-language result;
it also distinguishes exact fixed-scalar inputs from convention-wide may-read
sets and records tail transfer separately. Prototype recovery can therefore
prove a declared-void tail wrapper while SSA and reaching definitions still see
the result-register clobber. This rejected an earlier locally green but unsound
draft that removed the DEF.

A fresh empty-kit replay emitted 250/250 requested functions from all 224/224
binaries with zero extraction failures. Its worktree provenance label is
`49342c0+safe-void-clobber-worktree`; the final code commit will differ only in
tests and evidence documents, so this remains candidate evidence rather than a
commit-labelled release artifact. The package SHA-256 is
`f3277740fbfc0c3acea0fb6569648c1b40ece9b067abf8ded7b02a46cfa66125`,
the result-manifest SHA-256 is
`3d5d7e62cf9eaab0d4f6bdfbbc967119539ab6872f6a3d221f615d43ed207b1a`,
and the diagnostic-ledger SHA-256 is
`a345cb7d2f219f0a47e97fc47497f230566e84a8e6668fa344131521bbfe3593`.

Exactly 70 generated C files differ from the accepted literal-format package.
This breadth is expected from exposing previously anonymous `.plt.got` imports
and using exact fixed-library input evidence in caller/callee prototype
recovery; it is not hidden as a one-function change. Fresh full-corpus scores
are:

| Metric | Measured | Perfect | Mean | Median | Accepted direction |
|---|---:|---:|---:|---:|---|
| GED | 239 | 60 | 32.351464 | 10 | improves from 32.364017 |
| ByteMatch | 250 | 9 | 0.248819 | 0.219375 | improves from about 0.247702 |
| TypeMatch | 235 | 20 | 0.226702 | 0.083333 | regresses from 0.227412 |

The exact union remains 75/250. No exact win is lost. TypeMatch changes in only
one row, `libedit:O2-noinline:libedit.so.0.0:history_search_pos`, from `0.333333`
to `0.166667`; the new `history@plt` identity is verified against its exact
`GLOB_DAT` slot and exported body, so the alignment-sensitive metric loss does
not justify restoring an anonymous symbol. GED changes in six rows, three
better and three worse, with a net distance reduction of three. ByteMatch
changes in thirteen rows, nine better and four worse. `statdb_write` itself
improves from `0.392857` to `0.446429` and retains GED 4. The new ByteMatch
perfect `cronie:O0:crontab:env_free` was already GED-perfect, so it does not
raise the union. The largest byte regression is
`zlib:O2-noinline:minigzip:inflate_table`, `0.117552→0.009009`; its output still
compiles and the diff is dominated by stronger pointer types and temporary
renumbering, but this remains an explicit metric regression rather than a
claimed clean win.

The six-worker extraction took 104.244 seconds wall time and measured
2.526/2.772/13.339 seconds per-binary median/mean/maximum. The host still had
multiple unrelated multi-day CPU consumers, so these are provenance values,
not clean evidence for the Phase 1 performance guardrail.

Verification passes all 1,968 Rust library tests and every Rust integration
target, the real stripped `.plt.got` fixture, Rust and targeted Python
formatting/lint, and `git diff --check`. The architecture ratchet matches its
six-lane baseline exactly: 1,758 pass, 42 known fail, 228 structural, zero lane
errors. All 56 legacy and 64 curriculum executable behavior cells pass. The
cache-disabled 56/56-cell metric ratchet reports no per-cell GED, TypeMatch, or
ByteMatch regression against its checked corpus baseline. The
full Python run reached 100% and reported the four previously recorded
cross-sample `suspicious_win` content failures plus one expected tutorial
snapshot drift from ten to twelve real callgraph edges; the one-line evidence
update passes its focused verifier. Targeted `ty` remains at the same 30
pre-existing diagnostics and adds none for this test. Repository-wide Ruff
format remains independently red on 308 pre-existing files and is not relabeled
green; repository-wide Ruff lint and `ty` likewise retain their broad existing
debt (`ty`: 1,939 diagnostics). The required all-features Clippy invocation is
environment-blocked because the pinned Bitwuzla library path is unset; ordinary
all-target Clippy reaches the crate and remains red on 192 existing warnings,
with no warning in a newly added code hunk.

## 08:01–09:12 — deterministic convergence for aliased pointer contracts

The first commit-labelled replay of the `.plt.got` increment exposed a
reliability defect that the aggregate scores hid. Of 224 generated C files,
223 were byte-identical to the preceding worktree candidate, but
`libedit:O2-noinline:libedit.so.0.0:history_search_pos` alternated between
`char * arg0` and `long * arg0` across separate CLI processes. Five immediate
repetitions produced two distinct output hashes. The input binary, requested
VA, extension, and source revision were identical, so this was decompiler
nondeterminism rather than benchmark noise.

The cause was an unordered merge in authoritative pointer-parameter recovery.
Two exact aliases of `arg0` reached incompatible contracts: `history` supplied
`long *` evidence and `strstr` supplied `char *` evidence. Evidence was first
grouped by alias name and then immediately written back to the common source
origin while iterating a randomized `HashMap`; the last alias visited won.
This also explains why earlier runs disagreed about the row's TypeMatch score.

The RED unit test gives one source parameter two exact aliases and sends them
to conflicting `char *` and `long *` contracts. It reliably observed a pointer
before the repair. The retained implementation first resolves every alias to
its source origin, aggregates all pointee widths at that origin, and applies a
fact only if the complete set is compatible. Origin iteration uses a
`BTreeMap` for stable traversal. Conflicting evidence now fails closed to the
existing machine-word type instead of selecting either pointer arbitrarily.
The focused module has 15 passing tests, and ten independent real
`history_search_pos` CLI processes now produce the same SHA-256
`b36de3e944c5cee2f02b1158f130fd7a1e9a0c7a37a482f8e3d899b54d47c3fc`.

The reliability repair is commit
`17952f010ebb6f9fa0478f0e22084790379d55d2`. A fresh empty-kit replay labelled
with that exact commit emitted 250/250 functions across 224/224 binaries with
zero extraction failures. Its package is
`/tmp/glaurung-17952f0.pUJngv/results.zip`; the package SHA-256 is
`d7d59105e871227bde41e6b851846d02d20b07f88956d85a2f8032cc288cf4ba`,
the result-manifest SHA-256 is
`fe15b8e8d4578681072b55d7565cc26722051d19583e948913e9b71639f39219`,
and the diagnostics SHA-256 is
`37e0aca07dc49deadc696ce68a17f3b157752e03e66461ac70ab33310f7d7825`.
Extraction measured 2.304/2.482/12.819 seconds per-binary
median/mean/maximum.

Exactly one C file differs from the pre-repair commit-labelled package:
`bin_054.c` now declares `long arg0` and its exact copy as `long`, with an
explicit cast at the `history(long *, ...)` boundary. Its TypeMatch remains
`0.166667`, the conservative side of the formerly random result. TypeMatch
therefore retains the measured 235-row mean `0.226702`; GED and ByteMatch are
unchanged by this type-only CFG-equivalent, non-compiling row, so the preceding
60/239 GED perfects, nine ByteMatch perfects, and 75/250 union remain the final
candidate scores.

Final verification passes all 1,969 Rust library tests and every Rust
integration target, the real stripped `.plt.got` fixture, all 56 legacy and 64
curriculum executable behavior cells, and the six-lane architecture ratchet at
1,758 pass / 42 known fail / 228 structural / zero lane errors. The
cache-disabled metric ratchet against the pinned DecBench checkout reports no
per-cell regression across 56/56 cells. A first comparison accidentally used
the newer PR #56 refresh checkout against the older pinned baseline and
reported `arith:gcc:O0` GED `0→0.33` and `recursion:gcc:O2` GED `149→199.5`;
the authoritative checkout restores those values to `0` and `147.5`,
respectively. This is recorded as evaluator-version mismatch, not hidden as a
green retry or attributed to Glaurung.

## 09:12–10:14 — recover exact call-driven loop headers

The accepted candidate still rendered official
`dpkg:O2:dpkg-statoverride:statdb_write` as an infinite loop containing an
effectful iterator call and a conditional break. That C was executable, but
DecBench's CPG assigned six edges to it while the source loop has four. The
result was GED 4 even after the earlier `.plt.got` repair had removed the
incorrect return value and dangling terminal goto.

The repair recognizes only the exact lowered shape `while (1) { result =
call(...); if (exit(result)) break; remainder; }`. It rotates that loop into an
initial seed call followed by `while (!exit(result)) { remainder; result =
call(...); }`. The seed and latch preserve the number and ordering of calls;
the effect is not hidden in an expression. The transform fails closed unless
the first statement is one result-producing call, the second is a single-arm
break guard that reads that result, and the remainder contains no explicit
label, goto, or indirect goto that could bypass or re-enter the synthesized
latch. A real optimized and stripped host-GCC iterator fixture verifies that
both calls survive and that the recovered guard is no longer `while (1)`; a
unit negative control covers the unsafe goto case.

The implementation lives in the new focused `effectful_loop` module rather
than expanding `loop_form.rs`. The latter falls from 2,590 lines at the parent
revision to 2,556, while the new module is 220 lines including tests. Expression
register-use traversal is now the shared `Expr::contains_reg` helper instead of
a private copy embedded in the oversized loop-form module.

Exact scoring against the pinned canonical DecBench checkout gives these only
three changed rows relative to the accepted `17952f0` package:

| Function | GED | ByteMatch | Result |
|---|---:|---:|---|
| `chibios:clang:O0:chSemResetWithMessageI` | `76→74` | `0→0` | non-regressing |
| `betaflight:clang:O2:mspProcessInCommand` | `108→104` | `0→0.001692` | improves |
| `dpkg:gcc:O2:statdb_write` | `4→0` | `0.446429→0.578947` | new GED perfect |

TypeMatch is unchanged. The projected full aggregate is therefore 61/239 GED
perfects with mean `32.309623` and median 10, 9/250 ByteMatch perfects with mean
`0.249356` and median `0.219375`, and the existing 20/235 TypeMatch perfects
with mean `0.226702` and median `0.083333`. Because `statdb_write` was not
already perfect on another official metric, the exact union advances
75→76/250 (`30.4%`).

The implementation is commit
`83c6b07c0de9cf821f58517cd46d4d5ab8f44be0`. After rebuilding the extension
from that exact revision, a fresh empty-kit replay completed all 224 binaries
and all 250 functions with zero extraction failures. Its release archive is
`/tmp/glaurung-effectful-final.oRUVRE/results.zip`; the package SHA-256 is
`cb0b9c84366ea591c53d78fe68e003eb46a4178ccbf29e6ee23897395ad4b46c`,
the result-manifest SHA-256 is
`5031342f8ec50801c43cde3a2dd1110b2d2caca70ed5ba5e81cfa0bb946a1ec8`,
and the diagnostic-ledger SHA-256 is
`a0ae92ddd0f1b0df6a4266c13042b4502cbd5cff2915dca1fc7af8726b3c3155`.
The zip integrity check is clean. Differential inspection against the accepted
`17952f0` package confirms that only `bin_111.c`, `bin_166.c`, and `bin_174.c`
changed, exactly matching the three scored rows above.

The full Rust gate passes 1,971 library tests, every integration target, and
doctests after rebuilding with incremental compilation disabled and two build
jobs. The first attempt exhausted the worktree's disk quota during linking;
removing only the disposable Cargo target and rerunning produced the clean
result. The full Python suite reports 2,882 passed, 44 skipped, and the same
four unrelated `suspicious_win` cross-sample content failures recorded earlier;
no decompiler or loop test fails. The new real-binary test passes focused Ruff
format/lint and `ty`. Repository-wide Ruff format (349 existing files), Ruff
lint (3,710 existing findings), and `ty` (2,038 existing diagnostics) remain
red and are not represented as regressions introduced by this increment.

## 10:14–12:14 — make stack-address recovery follow control flow

The next immediate target in the exact-win cohort was official
`coreutils:O2-noinline:cp:copy_reg`. Its source has nine parameters, but the
accepted output declared 24. The authoritative register-input evidence already
contained only the six SysV register slots. The other fifteen parameters came
from outgoing-call frame addresses that stack promotion had mislabeled as
entry-stack arguments.

The root cause was duplicated stack analysis. `collect_label_stack_deltas`
followed labels, gotos, returns, and CFG joins, while
`collect_stack_address_defs` walked the structured text independently. After a
textually earlier epilogue, the latter continued into a later goto target with
an entry delta of zero. In `copy_reg`, an address that is really
`entry_rsp-400` was consequently recorded as `entry_rsp+104` and rendered as
`arg18`. The same false textual fallthrough affected 21 other official
functions.

The RED unit test builds the minimal shape: allocate a frame, branch to a label,
restore and return on textual fallthrough, then take an SP-relative address at
the target. Before the repair it produced `arg7`; after the repair it produces
the proved `local_10`. The implementation jointly solves label depths and
address aliases to a fixed point. The address walker restores state at labels
and invalidates it after goto, indirect goto, or return. The solve is bounded at
64 rounds and fails closed on non-convergence by discarding address aliases and
retaining only label depths derivable without them. This removes the second,
unsound notion of textual stack flow without making unresolved coordinates look
proved.

On the real stripped `copy_reg` binary, the signature is now exactly nine
parameters:

```c
unsigned int sub_8680(long * arg0, char * arg1, int arg2, char * arg3,
                      char * arg4, long * arg5, int arg6, long arg7,
                      long arg8)
```

Declarations fall `175→169`, temporaries `148→147`, undefined uses `6→5`,
and output size `31,338→30,981` bytes. The false undefined `local_190`
disappears. The five remaining undefined role names are pre-existing and remain
visible rather than being conflated with this repair.

A fresh 224-binary/250-function worktree extraction at
`/tmp/glaurung-stack-alias.AZq5As` completed without an extraction failure. Its
archive SHA-256 is
`804550427b7ebdb273c4e0c0b67deef9ae10084b59b0e48b432a4de2d58c74a7`.
Exactly 22 generated C files differ from the exact accepted loop-recovery
package. Focused evaluation covers every changed official row rather than a
favorable sample:

| Metric | Changed-row result | Aggregate consequence |
|---|---:|---:|
| GED | sum `964→955`; 2 improve, 20 equal, 0 regress | projected mean `32.309623→32.271966`; perfect count remains 61 |
| ByteMatch | sum `3.153678→3.204642`; 7 improve, 13 equal, 2 regress | projected mean `0.249356→0.249560`; compilable coverage `242→243` |
| TypeMatch | exact sum unchanged; all 22 equal | mean and perfect count unchanged |

The two ByteMatch regressions are retained and named:
`gnutls:O2-noinline:ocsptool:socket_open2` falls about `0.00596`, and
`x0r-usb:O2-noinline:x0r-usb:RemoteUSBThread` falls about `0.00128`. Both GED
rows are unchanged at zero and 29 respectively. Restoring their former stack
names would reintroduce aliases derived from impossible textual fallthrough, so
the safety proof takes precedence over those small compiler-similarity losses.
Notable gains include `copy_reg` ByteMatch `0.221953→0.226475`,
`grp_update` GED `51→46`, and `check_init_fifo` GED `40→36`. No exact metric
win is lost, so the 76/250 union is unchanged.

The 12-worker extraction took 60.707 seconds wall time, with
2.743/3.120/18.846 seconds per-binary median/mean/maximum. The immediately
preceding 12-worker package took 62.848 seconds with
2.915/3.299/14.490 seconds per-binary median/mean/maximum. This rules out an
obvious corpus-wide slowdown from the joint solve, but the shared host is too
contended to claim a performance improvement from those timings.

The full Rust gate passes 1,972 library tests, every integration target, and
doctests. The six-lane architecture ratchet matches its baseline exactly at
1,758 pass / 42 known fail / 228 structural / zero lane errors. The focused
output-canary capture confirms the intended `copy_reg` arity and health changes
with zero missing or invented CFG edges. All 56 legacy and 64 curriculum
executable cells pass. The cache-disabled metric ratchet reports no per-cell
GED, TypeMatch, or ByteMatch regression across all 56 cells.

The first combined gate attempt exhausted the user's temporary-filesystem quota
while two fixture-producing Python runs overlapped. Its Cargo and Python
failures were all explicit `Disk quota exceeded` errors, not product
assertions. Only this isolated worktree's reproducible `target/debug` build
cache was removed; source and benchmark evidence were retained. Clean isolated
reruns then produced the Rust, executable, architecture, and metric results
above. The full Python suite completes with 2,882 passed, 44 skipped, and the
same four unrelated cross-sample `suspicious_win` content failures recorded in
the preceding increment. Repository-wide Ruff format remains red on the same
349 files, Ruff lint on the same 3,710 findings, and `ty` on the same 2,038
diagnostics; no Python file changed in this increment.

The implementation and first evidence record are commit
`6a3252bdc03fea3ad9a8a898bdd39735460fb852`. After rebuilding the extension
from that clean revision, a second empty-kit replay reproduced every candidate
C file byte-for-byte and again emitted 250/250 functions from 224/224 binaries
without failure. The exact-revision archive is
`/tmp/glaurung-6a3252b.xo43Us/results.zip`; its SHA-256 is
`c6c55bc2227c486ec1237af506f26637bce1882c39ad02eb1ad01995b8a79936`,
the result-manifest SHA-256 is
`a5ba9d3b723b50168dd4b767e3f60a528dc3cb4ee21c32233b625a8cec3a8b76`,
and the diagnostic-ledger SHA-256 is
`f6232667261b76283bb9dc625873a17b66ac70a25038759dc27ed20bb859e37f`.
Zip integrity is clean. The replay took 59.882 seconds wall time, with
2.691/3.102/18.211 seconds per-binary median/mean/maximum.

The focused output-canary baseline was still pinned before the accepted
`console_getc`, `.plt.got`, effectful-loop, and stack-alias repairs. It is now
materialized from the exact clean implementation commit rather than leaving
those intended changes as permanent canary noise. The report SHA-256 is
`1bed38125724afaf7218f6225f2a3b695a46c7427fca3fb926a8b9de408d3ba0`.
Its four focused tests pass, the live capture matches every function and
provenance field, and focused Ruff format/lint is clean. Focused `ty` retains
the test file's two pre-existing missing-`pytest`-stub diagnostics; the revision
string update introduces no typed code.

## 12:15–12:56 — retain nested parser dispatches through verified raw loops

The next named target, `gnutls:O2-noinline:certtool:yyparse`, did not fail jump
table discovery. The stripped binary's signed-relative 88-slot PIC table was
already present as one LLIR `IndirectJump` with an explicit index and all 88 CFG
successors. The loss happened later: a candidate region contained the recovered
switch, but accounting rejected the outer parser loop's back edge and one nested
internal cycle, then replaced the complete function with `Unstructured`. The
renderer consequently printed one unrecovered indirect transfer and only 59 CFG
nodes against the source's 178.

The retained repair makes the existing lossless `RawLoop` contract explicit. A
natural loop containing exactly one resolved, index-bearing machine dispatch may
use the labelled-CFG fallback even when the dispatch is below an intermediate
guard. Its full block set owns every internal back edge; requiring a second
structured loop for a nested parser cycle would contradict the fallback's reason
for existence. Synthetic multi-successor CFGs remain on ordinary structured
switch recovery. During lowering, a conditional predecessor proves the table's
guard-default target; physical table slots with that same target coalesce into
one C `default` arm rather than inventing a case for every hole.

TDD uses a real host-GCC x86-64 assembly fixture with a signed-relative PIC
table, a separate guard block, three loop exits, and a nested internal cycle. It
proves eight CFG successors, verified raw-loop ownership, eight rendered cases,
and no unrecovered indirect transfer. Accounting and sparse-default unit tests
pin the two smaller contracts. A first full Rust run exposed an existing
synthetic switch-loop test that the broad detector had preempted; requiring an
explicit index-bearing indirect terminator restored that structured path. The
final Rust gate passes 1,975 library tests and every integration target.

An exact-revision fresh replay from commit
`22a3edc8876dc9f986da6f97c33ee810f1db12f9` emitted 250/250 requested functions
across 224/224 binaries with zero failures. Only three C files differ from the
accepted `6a3252b` package:

| Function | GED | ByteMatch | TypeMatch | Sparse switch |
|---|---:|---:|---:|---:|
| `base-passwd:O2-noinline:update-passwd:main` | `69→53` | `0→0` | `0.166667→0.166667` | 11 cases + default |
| `gnutls:O2-noinline:certtool:yyparse` | `601→236` | `0.075180→0.131599` | `0→0.05` | 75 cases + default |
| `shadow:O2-noinline:vipw:main` | `33→56` | `0→0` | `0.1→0.1` | 6 cases + default |

The changed-row GED sum improves `703→345`; ByteMatch and TypeMatch both rise,
and no exact win or union member changes. Projecting those exact deltas onto the
accepted stack-alias ledger moves GED mean about `32.271966→30.774058`,
ByteMatch `0.249560→0.249786`, and TypeMatch `0.226702→0.226915`. `vipw` is a
named GED regression: its source CFG has 21 nodes/33 edges, the old truncated C
had 18/25, and the complete switch has 25/44. Keeping the old score would require
discarding a resolved, recompilable 34-slot machine transfer, so the soundness
gain and large net structural improvement take precedence over that metric's
local source-shape preference.

The release archive is
`/tmp/glaurung-dispatch-22a3edc.ymC2zn/results.zip`, SHA-256
`5b3b655d3faf5fd128b35515d18543b8f5ced283172af36521fa9b66c8f01d74`.
The result manifest SHA-256 is
`f8b7767d9bdb9c598fe222f1db2ac8eaec63273b351e548eb0aadb70a4455119`;
the diagnostic ledger is
`49ff9bd34d1e5024742665fa86db545830c36de54d3917fbe81fcc96759ed71f`.
Zip integrity is clean. Eight-worker extraction took 75.819 seconds, with
2.474/2.673/13.394-second per-binary median/mean/maximum. The focused canary now
records `yyparse` structure fallbacks `1→0`, unresolved transfers `1→0`, and
undefined uses `27→23`, while keeping uncovered and invented CFG edges at zero;
its report SHA-256 is
`dec2356683c5cdd02cca039642db6c3dbef8fcaf7ccbd0f407b1f037c1075d17`.
The repository-wide Python gate collected 2,930 tests and completed with 2,882
passing, 44 skipped, and only the same four cross-sample `suspicious_win`
content failures recorded in the preceding increments. Focused canary tests and
Ruff format/lint pass; focused `ty` retains exactly the two pre-existing missing
`pytest`-stub diagnostics. `cargo fmt --check` and `git diff --check` are clean.

## 14:05–15:45 — separate ABI may-uses from proven call inputs

The next TypeMatch target exposed a missing program-level contract rather than
another spelling problem. In the stripped OpenSSH `ssh_agent_sign` chain, an
optimized wrapper leaves its first argument untouched in `rdi`, sets the later
arguments, and forwards all three to a project-local callee. The old choices
were both wrong: ignoring a conservative call recovered too few source inputs,
while treating all six SysV argument registers as reads invented parameters.

`CallEffects` now represents those two truths separately. `args` remains the
complete convention-wide may-use set, preserving sound liveness and dead-code
elimination. `proven_args` is a positive subset recovered from the callee's
definition and is the only non-exact call evidence consumed by signature and
parameter-view recovery. Exact catalog/declaration contracts continue to prove
all of their listed inputs. One shared `use_is_proven_input` query replaces the
previous whole-call exclusions in value numbering, integer parameter recovery,
and ARM VFP recovery, so those consumers cannot drift on what a call proves.
The recovered facts are attached before SSA in every public decompilation path,
and exact SSA identity carries a callee's pointer/scalar type back through an
untouched forwarding value without crossing an explicit conversion.

The first corpus replay found a real safety failure before the change was
accepted. `dpkg-statoverride`'s stripped `statdb_write(void)` became a six-
parameter function through a local variadic diagnostic helper. Its SysV
`va_list` prologue saved the unnamed register suffix; recursive recovery
mistook those optional values for fixed source parameters, then propagated the
mistake through allocation/error wrappers. The retained repair recognizes a
variadic prologue only when both adjacent ABI `gp_offset`/`fp_offset` constants
and the complete consecutive register-save suffix agree. It propagates only
the named fixed prefix and leaves actual optional arguments to call-site
reconstruction. A second fail-closed ABI rule rejects recovered SysV fixed
layouts after their first register hole. That turns impossible layouts such as
`[rdi, r8]` into the one proven prefix argument and `[rsi]` into no contract,
instead of recursively laundering caller-saved residue into a signature.

The exact official binary at `bin_174.elf:0x4800` now renders
`void sub_4800(void)` again. Its local no-argument helper is declared and called
with no parameters, while legitimate one- and two-argument callees retain their
contracts. Real stripped GCC fixtures cover the three-function pass-through,
the variadic register-save chain, pointer forwarding, and both integer and
pointer conversion boundaries. Rust tests separately prove that all six ABI
may-uses remain visible to def/use analysis while only the recovered subset is
source-signature evidence, and that SysV fixed evidence stops at a register
hole. Two adjacent correctness repairs also keep a reused stack-parameter home
from swallowing a later status value and recover known scalar pointee widths
from qualified C pointer spellings.

The cohesive demand-driven callee analysis moved out of the binding
orchestrator into `python_bindings/ir/callee_contracts.rs` (629 lines).
`python_bindings/ir.rs` falls from 3,969 to 3,731 lines at this revision; the new
owner contains definition discovery, bounded grandcallee facts, recovered
prototype construction, variadic classification, and pass-through refinement
rather than forwarding wrappers.

A fresh empty-kit replay at
`/tmp/glaurung-fixed-args.h1FbdZ` emitted 250/250 requested functions from all
224/224 stripped binaries with zero failures. `package.py` accepted the archive
and `unzip -t` found no error. The worktree-candidate archive SHA-256 is
`3fd7680cef4fb062380b471bb299edc276c0fc653307b99b3452424bc54bb223`;
the result manifest is
`d5b7722e10911567dd108568171fb8b4ef201ffd335600991848143cf679cd1d`,
and the diagnostic ledger is
`670461dfde5d3977c3aaf4d96616268bb6850d17bd79e69208961b309896cff9`.
Extraction took 65.680 seconds wall time at 12 workers, with
2.854/3.272/21.676-second per-binary median/mean/maximum. Exactly 100 generated
C files differ from the accepted `22a3edc` package, so the evaluation below is
the full candidate column, not a hand-picked changed-row sample.

Fresh official-metric evaluation from that package gives:

| Metric | Coverage | Perfect | Mean | Median | Zero |
|---|---:|---:|---:|---:|---:|
| TypeMatch, higher is better | 235 | 20 | `0.232220` | `0.083333` | 94 |
| corrected ByteMatch, higher is better | 250 | 14 | `0.302747` | `0.258810` | 36 |
| source-CFG GED, lower is better | 243 | 63 | `22.670782` | `10.0` | 63 |

ByteMatch recompiles 243/250 functions. The exact any-metric union is 77/250
(`30.8%`). Against the accepted dispatch package under the same fresh
TypeMatch/ByteMatch evaluation, TypeMatch rises from `0.225172` and ByteMatch
from `0.301802`. Against the unsafe pre-prefix candidate, GED improves four
rows, regresses none, and falls from `22.744856`; TypeMatch also rises from
`0.231031`, and ByteMatch from `0.302227`. The current TypeMatch is slightly
above the cited Ghidra `0.231` comparison, while GED remains about 2.24 edits
behind the cited Ghidra `20.43`. These are projected external results, not a
claim that PR #56 is merged or that the live board has recomputed every other
tool under the same current metric code. The Phase-1 TypeMatch and ByteMatch
targets are met; the GED target of at most 20 remains open.

The full Rust suite passes 1,981 library tests and every integration target.
The complete real decompiler fixture file passes. The six-lane architecture
ratchet matches its baseline exactly at 1,758 pass / 42 known fail / 228
structural / zero lane errors. Both executable behavior corpora pass every
required legacy and curriculum case, and the cache-disabled score campaign
reports no per-cell GED, TypeMatch, or ByteMatch regression across all 56/56
cells. Focused Ruff lint is clean; the test file's repository-wide formatting
debt and direct-file `ty` import/stub diagnostics predate this block. `cargo fmt
--check` and `git diff --check` are clean. The repository-wide Python run
collected 2,930 tests and retained exactly the established baseline: 2,882
passed, 44 skipped, and the same four cross-sample `suspicious_win` content
failures. Repository-wide static checks remain baseline-red outside this lane:
Ruff reports 3,509 existing findings and `ty` reports 1,939 diagnostics. The
exact committed-revision package is recorded after the remaining release step
rather than inferred from the worktree candidate.

The exact-revision replay from implementation commit
`a958b1f8c0bb73743aaa64fed7bc9a7c02e47688` is
`/tmp/glaurung-proven-calls.Ml0cCE/results.zip`. It again emits all 250/250
functions across 224/224 binaries, passes the package validator and `unzip -t`,
and every generated C file is byte-identical to the scored worktree candidate.
Only revision-bearing manifest/archive metadata changes. The exact-revision
archive SHA-256 is
`ef9f5e71c83439040cc25a71dfffb922d66458f13b778319c640f3e835c35d7c`;
the manifest is
`acddf321ac535c54c75c0e358c2306b4ab26f378af00aab0a1ea3fab09a248a0`,
and the diagnostic ledger is
`0d81d58919dd9dae3a170ac852ae47551da9b69289fe194607e7089fe501576e`.
The fresh metric results above therefore apply exactly to the committed
implementation rather than only to an uncommitted worktree state.

## 16:00–17:05 — remove x86 entry-register saves from source C

The largest fresh GED outlier, `shadow:O2-noinline:login:main`, exposed a
definedness defect before another structuring defect.  GCC's omit-frame-pointer,
stack-clash prologue saves `r15`, `r14`, `r13`, `r12`, `rbp`, and `rbx` below
the entry SP.  Stack promotion therefore names the distinct save locations
`local_*`, while the existing machine-frame cleanup recognized only `stack_*`
on x86.  Five incoming callee-save values consequently survived as undefined
`var0` through `var4` source inputs.

The retained cleanup accepts a promoted `local_*` only when its source is the
unversioned or SSA-zero canonical x86 nonvolatile register.  A later SSA
definition in the same architectural register is a real program value and is
preserved.  The caller supplies the detected calling convention, preventing
ARM's unrelated caller-saved `r12` from satisfying the x86 rule.  The existing
proof still requires the slot to be unread, or read
only by one dead restore, before deleting the pair.  This is deliberately not a
generic dead-local rule.

TDD first pinned the spill/restore shape and the later-definition near miss in
Rust.  A real stripped GCC shared-object fixture uses
`-fomit-frame-pointer -fstack-clash-protection`, clobbers all five extended
nonvolatile registers, and allocates a 9,000-byte volatile object.  Before the
repair its recovered C failed `-Werror=uninitialized`; after the repair it
recompiles and executes identically to the original for seven signed and
boundary seeds.  The full Rust library gate passes all 1,984 tests and every
integration target.  The
six-lane architecture gate remains exactly at 1,758 pass, 42 declared failures,
228 structural verdicts, and zero lane errors.

The official `login:main` health record improves without hiding CFG loss:

| Counter | Before | After |
|---|---:|---:|
| declarations | 254 | 242 |
| statements | 584 | 577 |
| temporaries | 231 | 226 |
| undefined names | 7 | 2 |
| raw physical registers | 2 | 1 |
| gotos | 98 | 98 |
| missing / invented CFG edges | 0 / 0 | 0 / 0 |

The fresh empty-kit candidate at `/tmp/glaurung-x86-frame.W24rx8` returns all
250 requested functions from all 224 binaries with zero extraction failures.
Seventy-three C files change: 70 ELF x86-64 outputs and three PE32-i386 outputs.
The archive passes the package validator and `unzip -t`; its SHA-256 is
`c748b405085b7d9d2b8eaece4ac6cecf48f263650f9f1459e4b726e9a2bd9ff1`.
The result manifest SHA-256 is
`49c2cca99e04d229d4b3de7bb31e05fa95153645d7aaba05bd026870a6ced906`
and the diagnostic ledger is
`a89e62cd1e64d1c5b2f73f6a71a916b126b293fb13eab341fa1d1b545cc5f898`.

Metric attribution required rejecting stale absolute columns.  The current
PR-56 refresh evaluator reports different absolute ByteMatch and VJ-GED values
for byte-identical stored C compared with the accepted replay; one identical
`rtmon` artifact, for example, appeared as GED 3 in the old overlay and 18 in a
fresh replay.  Fresh baseline and candidate columns were therefore recomputed
through the same code, source cache, toolchain, and empty checkpoint roots.
Those paired results are:

- GED is exactly unchanged on all 243 rows: both fresh columns have 62
  perfects, mean `27.679012`, and median `10` under this evaluator;
- ByteMatch changes only two rows, has the same 243 recompiles, nine perfects,
  and 52 zeros, and moves mean `0.250073232→0.250067085`;
- TypeMatch keeps 235 rows, 20 perfects, and median `0.090909`, but
  `diffutils:O2-noinline:diff3:output_diff3_edscript` loses one accidental
  positional match, moving mean `0.233963670→0.233659719` and zeros `93→94`.

Applying only those paired deltas to the accepted exact-revision ledger projects
GED unchanged at `22.670782`, ByteMatch at `0.302741`, and TypeMatch at
`0.231916`.  The 77/250 union is unchanged because no perfect row changes.  The
repair is accepted for definedness, recompilability, and source clarity rather
than claimed as leaderboard movement.  The evaluator drift itself reinforces
the still-open content-addressed cache/toolchain-fingerprint task; stale absolute
columns must not decide future patches.

The implementation and evidence were committed as
`be82d117da6239609a5f8a9ccacaa213520d7d28` and the remote branch was verified
at that exact object.  A new empty-kit replay built from the committed extension
returned all 250 functions across all 224 binaries with zero failures in 69.19
seconds.  All 224 generated C files are byte-for-byte identical to the scored
worktree candidate above, so its paired metric attribution applies to the exact
code commit.  The validated exact-revision archive SHA-256 is
`b7c636fc10887aeeec4827c369cf005b04d30b3d6c2418f8b218e587a66153e3`; the
result manifest is
`4fd768c519ef75d45e1782043d92709a1e6eb65a899d35823b937c1f44960d0c`, and the
diagnostic ledger is
`bfed83ae6ba619796566fad48ef434840f6636c639618f067a0237b804747e65`.
