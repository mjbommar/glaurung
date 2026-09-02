# Program Representations and Per-Function Fact Schemas in Binary Analysis Frameworks

Survey for Glaurung. Every URL below came from a fetch or search result; items I could not verify
against a primary source are marked UNVERIFIED.

---

## 1. Ghidra: P-Code, high P-Code, BSim, and the Program database

### 1.1 Raw p-code and refined/high p-code

P-code is Ghidra's architecture-neutral register-transfer IR
([P-Code Reference](https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pcoderef.html)).
The unit of data is a **varnode**: `(address space, offset, size in bytes)`, **untyped** — the opcode
imposes the integer/boolean/float interpretation. Spaces are `ram`, `register`, `const` (immediates are
offsets in a constant space), `unique` (temporaries). Each op reads input varnodes and writes exactly one
output. ~70 opcodes: integer/bitwise/comparison/float, `LOAD`/`STORE`, the branch-and-call family, and
`PIECE`/`SUBPIECE`/extensions.

The distinction that matters for measurement: **raw p-code** is the direct per-instruction translation;
**refined p-code** adds `MULTIEQUAL` (phi) and `INDIRECT` during data-flow construction, i.e. it is an SSA
graph. `HighFunction`
([javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html)) extends
`PcodeSyntaxTree` and adds `HighVariable` (varnodes merged into one program variable), `HighSymbol`,
`LocalSymbolMap`, `FunctionPrototype`, jump tables. Ghidra's ladder: **instruction → raw p-code → SSA
p-code → high p-code with variables/types/prototype → C AST**. License: Apache-2.0 (confirmed from
`LICENSE` in [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)).

### 1.2 BSim — the canonical p-code Ghidra actually measures over

The single most directly transferable design in this survey.

Per the [BSim tutorial](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_Intro.md):
vectors come from the decompiler; each feature is "a small piece of data flow and/or control flow"; and —
the key sentence — *"certain attributes, such as values of constants, names of registers, and data types,
are intentionally not incorporated into the features."* Comparison is **cosine similarity**. The database
stores signatures plus metadata, **not** disassembly or decompiled text.

Quarkslab's reverse-engineering
([BSIM explained once and for all](https://blog.quarkslab.com/bsim-explained-once-and-for-all.html))
supplies the mechanism:

- **Normalization first.** The decompiler runs a `normalize` action sequence — dead-code elimination
  (notably dead flag computations), stack-pointer abstraction, SSA conversion — producing high p-code.
- **Data-flow features by 1-dimensional Weisfeiler–Lehman.** Each varnode gets an initial hash from
  *byte width, defining operation, constant-ness, and whether it is a global or a function input* — not
  its register name and not its value. Three refinement iterations mix in the hashes of input neighbours.
  **Commutative ops (ADD, XOR, MULTIEQUAL) accumulate inputs order-independently**; non-commutative ops
  preserve operand order. "Shadow" varnodes (pure copies, phis whose inputs are identical) are dropped
  via dominator analysis.
- **Control-flow features.** Each basic block is seeded with `(in_degree << 8) | out_degree` — a purely
  structural, layout-independent label — then one WL iteration mixes predecessor hashes commutatively,
  with distinct constants for true/false edges. At each "root" op (`CALL`, `CALLIND`, `STORE`, `CBRANCH`,
  `RETURN`) the block hash is fused with the varnode expression hash.
- **Vector = a sorted multiset of 32-bit hashes** with occurrence counts (`1:545c6155`), weighted by an
  IDF table (512 buckets, learned from a corpus) times a `1 + log2(tf)` term-frequency term. Similarity is
  a weighted cosine where a shared feature contributes `min(coeff_A, coeff_B)^2`.

Config templates control the normalization: `medium_nosize` means *"size differences for varnodes of 4+
bytes aren't incorporated into BSim features"*, which is what makes 32↔64-bit matching work
([BSim CLI tutorial](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/BSimTutorial_BSim_Command_Line.md)).
Backends: H2, PostgreSQL, Elasticsearch; the interchange format from `generatesigs` is **XML**.

Record schema, read directly from
`Ghidra/Features/BSim/src/main/java/ghidra/features/bsim/query/description/`:

| Record | Fields |
|---|---|
| `FunctionDescription` | `exerec`, `function_name`, `address`, `sigrec`, `callrec` (list of `CallgraphEntry`), `id`, `vectorid`, `flags` |
| `ExecutableRecord` | `md5sum`, `executableName`, `architecture`, `compilerName`, `date`, `repository`, `path`, `rowid`, `flags`, `usercat`, `xrefIndex` |
| `SignatureRecord` | `sigvector` (`LSHVector`), `vectorid`, `count` (duplicates in db) |
| `DatabaseInformation` | `databasename`, `owner`, `description`, signature-strategy `major`/`minor`, `settings`, `execats`, `functionTags`, `layout_version`, `trackcallgraph` |

Note `major`/`minor`/`settings`: **BSim versions its signature strategy in the database**, because a
change to the normalization invalidates every stored vector. Any canonical form Glaurung ships needs the
same discipline.

### 1.3 FunctionID (FID) — the cheap end of the same idea

[fid.xml](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/FunctionID/src/main/doc/fid.xml)
defines two 64-bit hashes per function. **Full hash**: mnemonic + some addressing-mode info + specific
register operands, *but not the values of constant operands*. **Specific hash**: everything in the full
hash plus constant values, gated by a heuristic that tries to decide whether the constant is an address
(addresses excluded, real constants included). Scoring: 1.0 per ordinary instruction, 0 for calls and
NOPs, +0.67 per matching constant operand. Disambiguation uses parent/child function hashes in the call
tree. Storage: `.fidb` (internal format not documented in that file).

### 1.4 Program database model

A Ghidra `Program` is partitioned into managers: `Listing` (code units: instructions and data),
`Memory`, `SymbolTable`, `FunctionManager`, `ReferenceManager`, `BookmarkManager`, `EquateTable`,
`ExternalManager`, `RelocationTable`, `ProgramBasedDataTypeManager`
([Program javadoc](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html)).
`CodeManager` is the DB implementation for instructions/data with per-concern adapters. This is a
*persisted, versioned* object graph, not an export format — the export format is BinExport (§7).

---

## 2. Binary Ninja: BNIL, MLIL SSA, WARP

### 2.1 The BNIL ladder

[BNIL overview](https://docs.binary.ninja/dev/bnil-overview.html) lists eight forms: Lifted IL, LLIL,
LLIL SSA, Mapped MLIL, MLIL, MLIL SSA, HLIL, HLIL SSA. What each level removes:

- **LLIL vs Lifted IL**: removes NOPs and folds flags into conditionals; otherwise the same operations.
  (Flag folding is exactly the "dead flag computation" elimination BSim performs.)
- **MLIL** ([MLIL guide](https://docs.binary.ninja/dev/bnil-mlil.html)): *"registers have been translated
  to variables"*, *"the stack as a concept is not present"*, variables get types, call sites get typed
  parameters from platform info, data flow is computed and **constants are propagated**, some dead code
  is eliminated. A `Variable` has `source_type` (register / stack / flag), `storage` (register index or
  stack offset), `index`, and `type`.
- **MLIL SSA** adds `MLIL_VAR_PHI` and `MLIL_MEM_PHI` — the latter versions *memory* itself across
  merges, which is the piece most hand-rolled SSA implementations omit.
- **HLIL** adds high-level control flow constructs plus more dead-code/variable simplification.

MLIL-SSA therefore erases register allocation, stack-frame mechanics, flags and dead code, propagates
constants, and versions memory; it *keeps* operation identity, types, call structure, and the CFG.

License: the core is proprietary; the API repo
[Vector35/binaryninja-api](https://github.com/Vector35/binaryninja-api) is open. `.bndb` is documented only
at the API level (`FileMetadata` opens/creates it); the on-disk schema is not published
([API docs](https://api.binary.ninja/binaryninja.filemetadata-module.html)). UNVERIFIED: that `.bndb` is
SQLite-backed.

### 2.2 WARP — a portable function-identity GUID

[Vector35/warp](https://github.com/Vector35/warp), Apache-2.0 (confirmed from `LICENSE`), designed as a
*cross-tool* format. The spec, verbatim from the README:

- **Basic block GUID** = UUIDv5 over namespace `0192a178-7a5f-7936-8653-3cbaa7d6afe7` of the instruction
  bytes in execution order, after: (1) **zeroing all relocatable instructions** — any instruction with an
  operand used as a constant pointer into a mapped region, or that computes such a pointer with a constant
  offset; (2) **excluding all NOPs**; (3) **excluding register-set-to-self instructions that are
  effectively NOPs** (hot-patch padding) — architecture-sensitive: `mov edi, edi` is dropped on x86 but
  *not* on x86-64 because of implicit zero-extension.
- **Function GUID** = UUIDv5 over namespace `0192a179-61ac-7cef-88ed-012296e9492f` of the concatenated
  basic-block GUIDs **sorted by start address, highest to lowest**.
- **Constraints** disambiguate GUID collisions: `(ConstraintGUID, Option<i64> offset)` derived from called
  functions, calling functions, and adjacent functions, with the offset giving locality.

Serialization is **FlatBuffers**, chunked, with optional zstd compression (`rust/src/chunk.rs`). The
function record (`signature.fbs`) is remarkably small:

```
table Function {
  guid: FunctionGUID (required);
  symbol: SymbolBin.Symbol;      // name, class, modifiers
  type: TypeBin.Type;            // full type graph: int/float/bool/char/ptr/array/struct/union/enum/function
  constraints: [Constraint];     // (guid, offset)
  comments: [FunctionComment];   // (offset, text)
  variables: [FunctionVariable]; // (offset, name, LocationClass, type)
}
```

Two design points worth stealing: the identity key is content-derived and **stable across tools**, and it
is separated from the payload (symbol/type/vars/comments), so matching and knowledge transfer are distinct
concerns. Sorting block GUIDs makes the function GUID **block-layout independent** — canonical labeling,
achieved with a cheap total order.

---

## 3. angr: VEX, AIL, KnowledgeBase

### 3.1 VEX

angr lifts to **VEX** via pyvex ([IR docs](https://docs.angr.io/en/latest/advanced-topics/ir.html)):
`IRSB` blocks of `Ist_*` statements (`WrTmp`, `Put`, `Store`, `Exit`, `IMark`) over `Iex_*` expressions and
typed temporaries `t0..tn`. **Registers are offsets into a flat guest state array** (amd64 `rax` at offset
16) — the register name is already gone at the IR level. Flags use lazy **thunks** (`cc_op`, `cc_dep1`,
`cc_dep2`): a normalization in one direction, an obstacle in another (the thunk must be resolved to see
the real condition). Each IRSB carries a `jumpkind`. VEX is per-block SSA only — no cross-block phis.
angr also has a P-Code backend.

### 3.2 AIL

AIL is angr's decompiler IR, above VEX/P-Code
([decompiler docs](https://docs.angr.io/en/latest/analyses/decompiler.html)). Pipeline: CFG recovery →
calling-convention and stack-pointer analysis → lift to AIL per block → block simplification (constant
folding, copy propagation, dead assignment elimination, peephole) → function simplification (assignment
folding, local variable unification, call-expression folding) → variable recovery → type inference →
region identification and structuring → codegen. Same ladder, same normalizations, as Ghidra.

### 3.3 KnowledgeBase and angrdb

`KnowledgeBase` is a plugin hub. Plugin directory (read from the repo):
`functions`, `variables`, `xrefs`, `cfg`, `types`, `labels`, `comments`, `data`, `callsite_prototypes`,
`indirect_jumps`, `key_definitions`, `propagations`, `structured_code`, `patches`, `debug_variables`,
`obfuscations`, `custom_strings`, `bookmarks`.

Persistence is SQLAlchemy (`angr/angrdb/models.py`,
[docs](https://docs.angr.io/en/v9.2.73/_modules/angr/angrdb/models.html)):
`DbObject(main_object, path, content, backend, backend_args)`, `DbFunction(kb_id, addr, blob)`,
`DbCFGModel(kb_id, ident, blob)`, `DbVariableCollection(kb_id, func_addr, ident, blob)`,
`DbStructuredCode(kb_id, func_addr, flavor, expr_comments, stmt_comments, configuration, const_formats,
ite_exprs)`, `DbXRefs(kb_id, blob)`, `DbComment(addr, comment, type)`, `DbLabel(addr, name)`.
Note the **opaque `blob` columns** — angr's DB is a container for pickled/serialized plugin state, not a
queryable fact schema. This is the axis on which Glaurung's 34-table SQLite KB is already *ahead* of angr.

### 3.4 angr's bindiff — what it actually compares

Read directly from `angr/analyses/bindiff.py`:

- **Function attributes** used for the initial matching: `(number_of_basic_blocks, number_of_edges,
  number_of_subfunction_calls)`.
- **Block attributes**: `(distance_from_function_start, distance_from_function_exit,
  number_of_subfunction_calls)` — both are matched by Euclidean distance in that 3-space, i.e. purely
  structural, address-free coordinates.
- **Block equality** is decided on VEX: `IMark` statements are stripped, the statement lists must have
  equal length and matching tags, and a recursive structural comparison walks `__slots__` skipping `arch`
  and `_op`. Differences that are *only* in constant values are recorded as `ConstantChange(offset, a, b)`
  rather than treated as a mismatch. `NormalizedBlock` carries `statements`, `all_constants`,
  `operations`, `call_targets`, `jumpkind`.

The lesson: even angr's diff, built on a full symbolic-execution engine, matches on **shape +
operation multiset + jumpkind, with constants demoted to a diff annotation**.

License: angr is BSD-2-Clause (LICENSE header: Arizona Board of Regents / Emotion Labs / Microsoft).

---

## 4. Other IRs: BAP, Miasm, RetDec, Reko, REV.NG, Remill, MLIR efforts

| System | Representation | Normalizes away / keeps | Serialization | License |
|---|---|---|---|---|
| [BAP](https://github.com/BinaryAnalysisPlatform/bap) | **BIL** width-typed expression trees (`move/jmp/special/while/if/cpuexn` — `while`/`if` are *inside* the IR); **[Core Theory](https://binaryanalysisplatform.github.io/bap/api/master/bap-core-theory/Bap_core_theory/index.html)** tagless-final, rigidly sorted (`Bool`, `Bitv` by width, `Mem`, `Float`, `Rmode`); **BIR** term-level CFG (`sub/blk/arg/phi/def/jmp`) | keeps endianness and access size explicitly on loads/stores; SSA is an *optional* pass (`bap-ssa`) | **JSON, protobuf, textual, binary, XML** via piqi printers for `Stmt/Exp/Bil/Sub/Blk/Arg/Phi` | MIT |
| [Miasm](https://github.com/cea-sec/miasm) | expression trees width-typed via `.size`: `ExprInt/Id/Loc/Assign/Cond/Mem/Op/Slice/Compose`; `ExprOp` is n-ary with a *string* opcode | `AssignBlock` models one instruction as **simultaneous** assignments (clean xchg/rotate semantics); control flow carried as data in `IRDst`; SSA is a real pass | none (Python objects) | GPL-2.0 |
| [RetDec](https://github.com/avast/retdec) | `capstone2llvmir` → machine-level **LLVM IR** | SSA by construction. UNVERIFIED: the usual claim that registers become LLVM globals (design wiki errors out) | LLVM bitcode | MIT |
| [Reko](https://github.com/uxmal/reko) | two levels; `RtlInstruction` is documented as **transient** ("exist briefly while the binary is being scanned") before conversion to `Reko.Core.Code.Instruction` over expression trees (`SegmentedPointer`, `ConditionOf`, `TestCondition`, `MkSequence`, `Slice`) | **keeps** segmentation and condition-code semantics; SSA is explicit *and reversible* (`SsaTransform`/`UnSsaTransform`); 28-file unification/trait type inference | none | GPL-2.0 |
| [Remill](https://github.com/lifting-bits/remill) | instruction semantics written in C++, compiled to bitcode, instantiated per instruction through an explicit `State` struct | SSA over a *reified register file*, not over registers | LLVM bitcode | Apache-2.0 |
| [McSema](https://github.com/lifting-bits/mcsema) (archived 2022) / [Anvill](https://github.com/lifting-bits/anvill) | LLVM bitcode | — | protobuf CFG / protobuf function specs | AGPL-3.0 |
| [VAST](https://github.com/trailofbits/vast) | MLIR "tower of IRs": `ABI, Builtin, Core, HighLevel, LowLevel, Meta, Parser, Unsupported` | source is the Clang AST, i.e. the *upper* half of a binary→C pipeline | MLIR | Apache-2.0 |
| [Patchestry](https://github.com/lifting-bits/patchestry) | **Binary → Ghidra → p-code serialized as JSON → a P-Code MLIR dialect → ClangIR → C/LLVM** | a Ghidra plugin serializes decompiled p-code with types, control flow, operations and variables | **JSON** | Apache-2.0 |

**rev.ng deserves its own paragraph** ([revng/revng](https://github.com/revng/revng), GPLv2 overall, MIT
per-file) — it is the closest comparison to Glaurung's `program/` session model. Its **Model** is a
declared, versioned schema:
[model-schema.yml](https://raw.githubusercontent.com/revng/revng/master/include/revng/Model/model-schema.yml),
1838 lines, `version: 9`, `root_type: Binary` ([docs](https://docs.rev.ng/references/model/)).
`Binary` = `Architecture, OperatingSystem, PlatformName, EntryPoint, DefaultABI, TargetABI,
DefaultPrototype, Configuration, Binaries, Segments, Functions, ImportedDynamicFunctions,
TypeDefinitions`. `Function` = `Entry (MetaAddress), Name, Comment, StackFrame, Prototype, Attributes,
CallSitePrototypes, ExportedNames, Comments, LocalVariables, GotoLabels`. The type system separates
structural **Type** (`PrimitiveType, PointerType, ArrayType, DefinedType`) from identity-bearing
**TypeDefinition** (`CABIFunctionDefinition, RawFunctionDefinition, StructDefinition, UnionDefinition,
EnumDefinition, TypedefDefinition`) — and ships **two prototype flavors**: `CABIFunctionDefinition`
(carries an ABI) and `RawFunctionDefinition` (names the actual argument/return registers). Serialization is
**YAML** over a `TupleTree` that also provides `TupleTreeDiff`, `TupleTreePath`, `TupleTreeReference` and
change tracking — a diffable, path-addressable document. rev.ng's C emitter is **Clift**, an MLIR dialect
([Clift.td](https://raw.githubusercontent.com/revng/revng/master/include/revng/Clift/Clift.td)),
AST-shaped and region-based (every op `NoTerminator`), with full C syntax including `post_inc`, `comma`,
`ternary`, `goto`/`make_label`, and lvalue-ness and const-ness in the type system. Clift is explicitly
*not* a measurement form — it is a rendering IR.

---

## 5. Machine descriptions: SLEIGH, Sail, ASL

| Approach | What it produces | What it makes explicit / normalizes | License |
|---|---|---|---|
| [SLEIGH](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) (descends from SLED + UQBT's SSL) | **p-code**, ~60 ops, flat 3-address over varnodes, untyped beyond size, not SSA. Constructors have five sections: table header, display, bit pattern, disassembly actions, semantics. `.slaspec`/`.sinc` → `.sla` | stated design goals are machine independence and **"explicit data manipulation and no indirect effects"** — flags, implicit stack adjustments and side effects must all be written out | Apache-2.0 |
| [Binary Ninja arch plugins](https://binary.ninja/2021/12/09/guide-to-architecture-plugins-part2.html) | no DSL: `get_instruction_low_level_il(data, addr, il)` where `il` is both accumulator and expression factory, each call returning an expression index | LLIL is an expression *tree* (`eax = eax + ecx*4` is one instruction); `LLIL_MEM_PHI` versions memory in SSA form | proprietary core |
| [GDSL](https://github.com/gdslang/gdsl-toolkit) / [RREIL](https://github.com/gdslang/gdsl-toolkit/wiki/RReil) ([paper](http://www2.in.tum.de/bib/files/kranz13gdsl.pdf)) | decoder DSL compiled by MLton into generated C frontends, targeting **RREIL** (~22 instructions) | translates a **whole basic block at a time**, so cross-instruction dead-flag elimination works: an Intel `ADD` needs >10 RREIL instructions for flag effects, and liveness gives "code reduction by as much as 50%" | BSD-style 3-clause text; SPDX id UNVERIFIED |
| [Sail](https://github.com/rems-project/sail) | dependently/refinement-typed over bitvectors (widths in the type system); emits C/OCaml emulators, Coq/Isabelle/HOL4, Lem, JSON. Models: Armv9.4-A/v8.5-A (from Arm ASL), official [RISC-V](https://github.com/riscv/sail-riscv), CHERI, x86-from-ACL2 | machine-checkable ground truth | BSD-2-Clause |
| ARM ASL: [asl-interpreter](https://github.com/alastairreid/asl-interpreter), [asl_to_sail](https://github.com/rems-project/asl_to_sail) → [sail-arm](https://github.com/rems-project/sail-arm) | Arm's machine-readable spec translated into Sail | — | BSD-3-Clause / UNVERIFIED |

Rust access to SLEIGH is immature: [rbran/sleigh-rs](https://github.com/rbran/sleigh-rs) (MIT, parses
`.slaspec`, self-described "unfinished, and is not ready for use"),
[rbran/sleigh2rust](https://github.com/rbran/sleigh2rust) (MIT), and
[mnemonikr/libsla](https://github.com/mnemonikr/libsla) (Apache-2.0, FFI to the C++ sleigh).

Across §5 there are three ways to get semantics: hand-written lifters (Miasm, Reko, RetDec, Remill, Binary
Ninja, Glaurung today), declarative machine descriptions (SLEIGH, GDSL), and formal ISA specifications
(Sail, ASL). Only the last gives machine-checkable ground truth; only SLEIGH has a large free corpus of
processor definitions. Neither is on Glaurung's critical path for *measurement*; both matter for
*differential validation* of the lifter, which is what makes a canonical form trustworthy.

---

## 6. Canonical/normalized forms used for comparison

There is a clean spectrum here, and how much is masked is *inversely* correlated with how much structural
machinery is added back.

**Masking almost nothing.** [Asm2Vec](https://dmas.lab.mcgill.ca/fung/pub/DFC19sp.pdf) (S&P 2019) has
exactly one rule: *"constants tokens are normalized into their hexadecimal form."* Registers and memory
expressions are kept literally. Robustness comes from structure instead: selective callee inlining
(inline callee `f_c` into `f_s` iff `len(f_c)/len(f_s) < 0.6`, or `f_s` is under 10 instructions; library
calls never inlined), edge-coverage sequence generation, and random walks. Reference implementation in
[Kam1n0-Community](https://github.com/McGill-DMaS/Kam1n0-Community), Apache-2.0.

**Masking selectively, by role.** [SAFE](https://arxiv.org/pdf/1811.05296) (DIMVA 2019) replaces base
memory addresses with `MEM` and immediates with `|value| > 5000` with `IMM`, but explicitly leaves
`mov EAX,[EBP-8]` alone — a stack displacement identifies a local variable and must survive, whereas a
jump displacement is noise. (The [SAFE repo](https://github.com/gadiluna/SAFE) `LICENSE` is a bare
two-line copyright notice with no grant of rights — effectively unlicensed.)
[jTrans](https://arxiv.org/pdf/2205.12713) (ISSTA 2022, [code](https://github.com/vul337/jTrans), MIT)
maps strings → `<str>`, constants → `<const>`, **internal** call names → `<function>` while **keeping
external** call names (stable interfaces survive versions, internal ones don't), and rewrites each jump
source token to `JUMP_XXX` where XXX is the *ordinal index of the target token*.
[PalmTree](https://arxiv.org/pdf/2103.03809) (CCS 2020, MIT) masks constants of ≥5 hex digits to `[addr]`
while **keeping small constants**, on the same local-variable/field-offset rationale as SAFE.
[DeepSemantic/WIN](https://arxiv.org/html/2106.05478) has the most explicit rule table in the literature:
immediates split by *role* (`libc[name]`, `self`, `innerfunc`, `externfunc`, `jmpdst`, `dispstr`,
`dispbss`, `dispdata`, `immval`), registers by *size* (`reg[1|2|4|8]`), pointers by width and indirection;
17,225-token vocabulary; license UNVERIFIED. [FASER](https://arxiv.org/pdf/2310.03605) (MIT) normalizes
once over radare2 ESIL rather than per architecture, and usefully ablates *with and without* register
normalization.

**Masking almost everything lexical.** The **ACFG** of
[Genius](https://www.cs.ucr.edu/~heng/pubs/genius-ccs16.pdf) (CCS 2016) and
[Gemini](https://arxiv.org/pdf/1708.06525) (CCS 2017) reduces each basic block to **eight attributes: six
block-level statistical** — string constants, numeric constants, no. of transfer instructions, no. of
calls, no. of instructions, no. of arithmetic instructions — **and two structural** — no. of offspring,
betweenness centrality. Every opcode and operand is discarded; a block is six counts plus two graph
positions. Gemini reports that "only basic block-level attributes and the number of offspring" suffice,
dropping betweenness as too expensive. (Searched for "sigma normalization" as a term of art: it does not
exist; the nearest referent is Genius's attribute set Σ.)

**Graph forms over compiler IR.** inst2vec's **XFG**
([NeurIPS 2018](https://proceedings.neurips.cc/paper_files/paper/2018/file/17c3433fecc21b57000debdf7ad5c930-Paper.pdf),
[ncc](https://github.com/spcl/ncc), BSD-3-Clause) is a directed multigraph over LLVM SSA whose nodes are
*variables or label identifiers* and whose edges are data or execution dependences; preprocessing maps
identifiers → `%ID`, immediates → `<INT>`/`<FLOAT>`/`<STRING>`, and inlines struct contents, keeping types
and opcodes. The authors note XFGs are not meant to be compiled, "which allows us to introduce **ambiguity
(e.g., ignoring parameter order)** in favor of preserving context."
[ProGraML](https://arxiv.org/pdf/2003.10536) (ICML 2021,
[code](https://github.com/ChrisCummins/ProGraML), Apache-2.0) goes the other way — deliberately flow-,
position- *and* value-sensitive. Verified against its
[protobuf](https://raw.githubusercontent.com/ChrisCummins/ProGraML/development/programl/proto/program_graph.proto):
node types `INSTRUCTION, VARIABLE, CONSTANT, TYPE`; edge flow types `CONTROL, DATA, CALL, TYPE`; and
**every edge carries an integer `position`** encoding branch order for control edges and **operand order**
for data edges. Each unique variable and constant is its own vertex. Serialization: protobuf.

**VEX normalization.** [VexIR2Vec](https://arxiv.org/pdf/2312.00507)
([code](https://github.com/IITH-Compilers/VexIR2Vec), AGPL-3.0) is the most directly transferable rule set,
motivated by VEX having ~1095 opcodes and "about 100 different ways to write an addition". Six
canonicalization rules: (1) same-semantics opcodes collapse (`Add8|Add16|Add32` → `Add`); (2) **operand
bitwidths and endianness masked out**, casts like `32uto64` removed; (3) negative immediates converted to
positive (`add(-1,t)` → `sub(+1,t)`); (4) types reduced to four primitives (Integer, Float, Double,
Vector); (5) constants, variables and registers abstracted to a generic representation; (6) indirect
memory accesses replaced with direct. Then **VexINE** applies compiler-style passes to straight-line
"peepholes": register promotion, redundant-write elimination, copy propagation, constant
propagation/folding, CSE, load-store and store-store elimination, with the rule that values used-but-not-
defined in a peephole are parameters and must survive. The authors are explicit that these are local and
**unsound** — *"soundness is not important in this context: the normalizations are designed to reduce the
differences in IR generated from different architectures and compilers."* That sentence is the honest
statement of what a similarity canonical form is for, and why it must be a separate artifact from the IR
the decompiler renders.

**Formula-level.** [BinSim](https://faculty.ist.psu.edu/wu/papers/BinSim.pdf) (USENIX Sec 2017) discards
tokens entirely: traces are lifted to Vine IL, syscall sequences aligned, backward slices taken from
matched syscall arguments, **weakest preconditions** computed along each slice and handed to STP for
conditional equivalence. Motivated by the observation that block-centric symbolic comparison fails when
semantics spread across basic blocks.

**Two findings worth flagging.** (i) The reproduction study
[Marcelli et al., USENIX Sec 2022](https://www.usenix.org/system/files/sec22fall_marcelli.pdf)
([artifacts](https://github.com/Cisco-Talos/binary_function_similarity), MIT) found that instruction
embeddings over normalized assembly **did not beat a bag-of-words of opcodes** or hand-engineered features
as GNN node inputs, at much higher training cost. (ii) The 2024+ generation is abandoning explicit
normalization: [BinaryAI](https://arxiv.org/html/2401.11161v3) (ICSE 2024) documents no normalization
rules at all and lets an LLM encoder absorb the variance.

---

## 7. Serialized per-function fact schemas — and what recurs

### 7.1 BinExport2 (Google, Apache-2.0)

[google/binexport](https://github.com/google/binexport), consumed by BinDiff and VxSig; exporters for IDA
Pro, Binary Ninja, and Ghidra. The schema
([binexport2.proto](https://raw.githubusercontent.com/google/binexport/main/binexport2.proto)) is a
**fully interned, index-addressed** protobuf: top-level repeated arrays of `expression`, `operand`,
`mnemonic`, `instruction`, `basic_block`, `flow_graph`, plus one `call_graph`, a `string_table`,
`comment`, `section`, `library`, `module`, `data_reference`, and an `md_index` extension — every reference
is an `int32` index. The proto's stated goal: *store every unique expression, mnemonic, operand,
instruction and basic block only once*. Key fields, verbatim:

- `CallGraph.Vertex`: `address`, `type` (NORMAL / LIBRARY / IMPORTED / THUNK / INVALID), `mangled_name`,
  `demangled_name`, `library_index`, `module_index`. `CallGraph.Edge`: `source_vertex_index`,
  `target_vertex_index`.
- `FlowGraph`: `basic_block_index[]`, `entry_basic_block_index`, `edge[]` where
  `Edge = (source_basic_block_index, target_basic_block_index, type ∈ {CONDITION_TRUE, CONDITION_FALSE,
  UNCONDITIONAL, SWITCH}, is_back_edge)` — **back edges are precomputed by Lengauer–Tarjan and stored**.
- `Instruction`: `address`, `call_target[]`, `mnemonic_index`, `operand_index[]`, `raw_bytes`,
  `comment_index[]`.
- `Operand`: `expression_index[]`. `Expression`: `type` (SYMBOL / IMMEDIATE_INT / IMMEDIATE_FLOAT /
  OPERATOR / REGISTER / SIZE_PREFIX / DEREFERENCE), `symbol`, `immediate`, `parent_index`,
  **`is_relocation`** — operands are *expression trees*, not strings, and relocation-ness is a first-class
  bit (the same fact WARP uses to decide what to zero).
- `BasicBlock`: `instruction_index[]` as `IndexRange(begin, end)` pairs.

### 7.2 BinDiff (Apache-2.0)

[google/bindiff](https://github.com/google/bindiff),
[concepts.md](https://github.com/google/bindiff/blob/main/docs/concepts.md). BinDiff deliberately
*"works on the abstract structure of an executable, ignoring the concrete assembly-level instructions"*.
Each function's signature is **(number of basic blocks, number of edges, number of calls to
sub-functions)** — the same triple angr chose independently. Matching is a quality-ordered ladder: hash,
name hash, **edges flow-graph MD index**, edges call-graph MD index, MD index, prime signature, call-graph
MD index, edges-proximity MD index, relaxed MD index, address sequence, string references, loop count,
call sequence; basic blocks use edges prime product, hash/prime, MD index variants, propagation last. The
**MD index** takes a topological graph ordering as input, parametrized top-down (from entry) or bottom-up
(from exits) — a structural invariant over the flow graph and call graph. Function similarity ≈ 50%
edge/block/instruction quotas + 50% MD index difference; binary similarity weights edges ~35%, blocks
~25%, call-graph MD index ~20%. Origin:
Flake/Dullien & Rolles, *Structural Comparison of Executable Objects* (DIMVA 2004) and *Graph-based
comparison of Executable Objects* (SSTIC 2005) —
[dblp record](https://dblp.org/rec/conf/dimva/Flake04.html),
[BinDiff manual](https://www.zynamics.com/bindiff/manual/).

### 7.3 Diaphora (AGPL-3.0)

[joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) exports **one SQLite DB per binary**.
The `functions` table is the most complete published per-function fact schema in the field; read directly
from `db_support/schema.py`:

```
name, address, nodes, edges, indegree, outdegree, size, instructions, mnemonics, names,
prototype, prototype2, cyclomatic_complexity, primes_value, comment, mangled_function,
bytes_hash, function_hash, bytes_sum, kgh_hash, md_index,
pseudocode, pseudocode_lines, pseudocode_hash1/2/3, pseudocode_primes,
assembly, clean_assembly, clean_pseudo, assembly_addrs,
microcode, clean_microcode, microcode_spp, mnemonics_spp,
strongly_connected, strongly_connected_spp, loops, switches,
tarjan_topological_sort, constants, constants_count,
function_flags, rva, segment_rva, source_file, userdata, export_time
```

plus `basic_blocks`, `bb_relations(parent_id, child_id)`, `bb_instructions`, `function_bblocks`,
`instructions(address, disasm, mnemonic, operand_names, …)`, `callgraph(func_id, address, type)`,
`constants(func_id, constant)`, `compilation_units`, and `program(callgraph_primes,
callgraph_all_primes, processor, md5sum)`.

The `clean_*` columns are the normalized forms. `get_cmp_asm()` in `diaphora.py` gives the masking rules:
strip comments after `;` or ` # `; replace auto-generated names (`sub_`, `byte_`, `dword_`, `loc_`, …) and
their hex suffix with `XXXX`; drop `dword ptr`/`byte ptr` size prefixes; replace `+<hex>h+` displacements
with `+XXXX+`; collapse `aName_123` string labels to `aXXX`. "Small primes product" (SPP) encodes a
multiset of mnemonics or microcode ops as a product of primes — an order-independent commutative multiset
hash, the same invariance goal as BSim's commutative WL mixing, reached arithmetically.

### 7.4 DecBench

[decbench.com/about](https://decbench.com/about/) (fetched via curl; WebFetch is 403'd). 94,575 functions,
803 binaries, 13 decompilers, 3 metrics as of the 2026-08-29 snapshot. The three per-function metrics:

1. **Structural correctness = Graph Edit Distance.** Joern lifts *both* the original source and each
   decompiler's C output to a control-flow graph; the score is the number of node/edge
   insertions/deletions/substitutions needed to make them isomorphic. **Node labels are ignored — only
   control-flow shape is scored.** Perfect = GED 0 = graph-isomorphic.
2. **Type correctness.** Recovered variables are matched to DWARF ground truth: arguments **by ABI
   position**, stack locals **by calibrated frame offset**, the remainder by name; score = fraction of
   types correct.
3. **Byte-match recompilability**, with distance measured as assembly lines that must change.

Ranked by **Union** (perfect on at least one). This is the clearest statement in the field that
*measurement is defined over a canonical graph plus a typed variable table*, not over text.

### 7.5 SARIF 2.1.0 (OASIS standard, JSON)

[Spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os.html);
[JSON Schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json).
Field lists extracted from the schema itself:

- `address`: `absoluteAddress`, `relativeAddress`, `offsetFromParent`, `length`, `kind`, `name`,
  `fullyQualifiedName`, `index`, `parentIndex` — a **hierarchical** address model (section → function →
  block) built for binaries.
- `logicalLocation`: `name`, `fullyQualifiedName`, `decoratedName`, `kind`, `index`, `parentIndex`.
- `result`: includes `fingerprints` and `partialFingerprints`, `baselineState`, `correlationGuid`,
  `codeFlows`, `graphs`, `graphTraversals`, `rank`, `taxa`.

SARIF is a **findings container**, not a program representation, but `partialFingerprints` +
`baselineState` are exactly the machinery needed to say "this finding is the same finding across two
builds" — the finding-level analogue of a function GUID.

### 7.6 What recurs across all of them

Take the intersection of BinExport2, BSim, WARP, Diaphora, angr's bindiff, BinDiff, and FID. Every one of
them, independently, stores per function:

1. A **content-derived identity hash** computed after masking addresses/relocations (WARP GUID, FID
   full hash, Diaphora `bytes_hash`/`function_hash`/`kgh_hash`, BSim `vectorid`).
2. **CFG shape**: block count, edge count, edge kinds, back edges, entry block. Nobody stores block
   *order*; everybody stores block *relations*.
3. **Call-graph position**: callees, callers, call count. WARP promotes this to a first-class matching
   constraint; BinDiff, FID, and Diaphora all use it for disambiguation.
4. A **multiset of operations** (mnemonics or IR opcodes), deliberately order-insensitive: Diaphora's
   SPP, BSim's commutative WL, angr's `operations` list.
5. **Constants and string references, kept separately from the identity** — used to disambiguate or to
   diff, never (except FID's "specific hash") folded into the primary key.
6. A **prototype/type record**: return type, parameters by ABI position, locals by storage offset.
   BinExport2, WARP, Diaphora, DecBench, and Ghidra all key locals by *storage location*, not by name.
7. **Provenance metadata**: architecture, compiler, build/ingest identity (BSim's `ExecutableRecord`;
   Diaphora's `program` table; BinExport2's `Meta`).
8. **Interning**: BinExport2's index-addressed arrays, Ghidra's data-type manager, WARP's chunked
   FlatBuffers, Glaurung's own interned type store. Nobody serializes strings inline at scale.

And what is *always* thrown away: register names/allocation, block layout order, absolute addresses,
relocation targets, NOPs and padding, dead flag computations, stack-frame mechanics, and (except in
"specific"-hash variants) constant values.

---

## 8. E-graphs and equality saturation

**Can an e-graph over LLIR give a canonical representative up to algebraic rewrites?** In principle yes;
in practice nobody has done it on machine code, and the tooling would need adapting.

[egg](https://github.com/egraphs-good/egg) (MIT, [POPL 2021](https://arxiv.org/abs/2004.03082)) holds a
congruence relation as e-classes of e-nodes over a union-find of `Id`s, with **deferred rebuilding**
(congruence restoration batched at iteration boundaries) and **e-class analyses** (a semilattice per class
with `make`/`merge`/`modify`). The canonical representative is chosen at **extraction**: cheapest term per
class under a `CostFunction` — built-in `AstSize` and `AstDepth`, plus ILP extraction (`LpExtractor`).
Serialization: s-expressions (`RecExpr`). [egglog](https://github.com/egraphs-good/egglog) (MIT,
[PLDI 2023](https://arxiv.org/abs/2304.04332)) stores data as **partial functions rather than relations**,
so congruence falls out of functional-dependency maintenance and e-matching becomes relational and
incremental. Serialization: s-expression Datalog.

[Cranelift's aegraph mid-end](https://github.com/bytecodealliance/rfcs/blob/main/accepted/cranelift-egraph.md)
(Apache-2.0 WITH LLVM-exception; also [Fallin's writeup](https://cfallin.org/blog/2026/04/09/aegraph/)) is
the version that survives contact with a production compiler. An **acyclic e-graph** applies rewrites
eagerly at node-creation time only, joining rewritten forms to the original with **union nodes** inside the
existing SSA value space — no rebuilding, no parent pointers, no two-level structure. Control flow is pure
e-nodes plus a per-block side-effect skeleton; rules are ISLE. One fixpoint-free pass does GVN, constant
folding, algebraic simplification, LICM, redundant-load elimination, DCE and rematerialization. Reported
average e-class size after rewriting: **1.13 e-nodes** — a useful reality check on how much algebraic
variation is actually there.

[Souper](https://github.com/google/souper) (Apache-2.0, [paper](https://arxiv.org/pdf/1711.04422.pdf))
shows the shape of the canonical slice: its `Inst` IR is a textual bitvector-expression format
(`cand`/`infer`/`result`/`pc`/`blockpc`), harvested by walking *backwards* from an LLVM value into a
**hash-consed DAG of pure bitvector ops**, with anything unmodelable becoming an opaque `var`. Memory,
calls, names, non-bitvector types and the CFG are abstracted away; control flow survives only as
`block`/`phi` plus path conditions, and dataflow facts (`knownBits`, `nonZero`, `range`, …) attach to vars.
[Ruler](https://github.com/uwplse/ruler) (MIT, OOPSLA 2021) *infers* rewrite rules via **characteristic
vectors implemented as an egg e-class analysis** — e-classes with identical cvecs (observational
equivalence on a fixed input sample) become candidate equalities.
[Diospyros](https://github.com/cucapra/diospyros) (MIT, ASPLOS 2021) canonicalizes *data movement*,
holding every equivalent lane assignment in one e-graph rather than committing early.

**The honest negative.** After extensive search — including sweeps of the EGRAPHS 2023-2026 programs and
`awesome-egraphs` — **there is no published system using e-graphs or equality saturation for binary
lifting or decompilation.** The only e-graph-on-binary-artifacts line is MBA deobfuscation, which
simplifies *expressions extracted from* binaries rather than recovering structure:
[Improving MBA Deobfuscation using Equality Saturation](https://secret.club/2022/08/08/eqsat-oracle-synthesis.html),
[Lee, Jeon, Cho](https://arxiv.org/abs/2404.05431), and
[mazeworks-security/Simplifier](https://github.com/mazeworks-security/Simplifier) (GPL-3.0; its eqsat path
is currently disabled). Adjacent work runs eqsat over *instruction semantics* for instruction selection
([MISAAL](https://charithmendis.com/assets/pdf/25-pldi-misaal.pdf), PLDI 2025) or ISA design
([ISAMore](https://uv-xiao.github.io/assets/pdf/isamore_asplos26.pdf), ASPLOS 2026), and
[*There and Back Again*](https://arxiv.org/abs/2404.00786) (LATTE'24) does *hardware* decompilation
(netlist → RTL) with e-graphs — the nearest structural analogue. Ghidra's own `rulecompile.cc` is a
hand-written **destructive** term rewriter, not an e-graph. Verified negatives: no e-graph work in angr,
BAP, Remill, or Binary Ninja; verified-lifting work (Verbeek et al. PLDI'22, "Formally Verified Binary
Lifting to P-Code" CCS'24) is theorem-prover based.

The gap is real, but Cranelift's 1.13-e-nodes-per-class result suggests the payoff for *similarity* is
modest against the cost — which is why it ranks last in §9(d).

---

## 9. SYNTHESIS

### (a) The representation ladder every mature framework converges on, and where Glaurung sits

Five levels, in every framework surveyed:

| Level | Ghidra | Binary Ninja | angr | BAP | rev.ng | Reko | **Glaurung** |
|---|---|---|---|---|---|---|---|
| L0 machine | Listing / CodeUnit | disassembly | capstone/pyvex | disasm | — | MachineInstruction | iced-x86 / capstone |
| L1 flat RTL, untyped, per-instruction | raw p-code | Lifted IL / LLIL | VEX IRSB | BIL / Core Theory | LLVM (QEMU tiny) | RtlInstruction (transient) | **LLIR `Op`** |
| L2 SSA over L1 | refined p-code (`MULTIEQUAL`) | LLIL SSA | (none; per-block only) | BIR + `bap-ssa` | LLVM SSA | `SsaTransform` | **`value_number` + `copy_prop`** |
| L3 variables + types + prototypes | high p-code (`HighFunction`) | MLIL / MLIL SSA | AIL after variable+type recovery | BIR + KB | **Model** (`Function`, `TypeDefinition`) | `Reko.Core.Code` + Typing | **`program/` type store, `mir`, `stack_locals`, `types_recover`** |
| L4 structured C AST | decompiler C | HLIL | structured AIL | — | Clift | AST | **`structure_v2` + `ast`** |

Glaurung's LLIR straddles L1/L2. Reading `src/ir/types.rs`: `Op` is flat three-address
(`Assign/Bin/Un/Cmp/Load/Store/Jump/CondJump/Call/...`) over `VReg` and `Value`, with `MemOp` carrying
base/index/scale/disp/size/segment/endian. That is structurally the same shape as p-code, with two
differences that matter for canonicalization:

1. **`VReg::Phys(String)` carries the architectural register name all the way through.** Ghidra's varnode
   is `(space, offset, size)`; BSim's initial hash uses *byte width, defining op, constant-ness, and
   global/input status* and explicitly not the register name. Glaurung's canonical form must project
   `Phys(name)` away.
2. **`Width` is not derivable for `VReg::Temp`** (`VReg::width()` returns `None` for temporaries). BSim's
   varnode seed *requires* a width. This is a concrete prerequisite: either widen `Temp` to carry a width,
   or thread widths through the SSA pass.

One further observation: `BinOp` mixes levels — `LogicalAnd`/`LogicalOr` are documented as source-level
short-circuit operators sitting alongside bitwise `And`/`Or`. For a canonical form these must be distinct
labels (they are not the same operator), and their presence signals that the value has already passed
through structuring. Prefer to canonicalize *before* L4 introduces them.

Glaurung is also, already, ahead of most of the field on one axis. angr's `angrdb` stores opaque `blob`
columns; Miasm, RetDec and Remill serialize nothing. Only rev.ng's YAML `Model`, BAP's piqi-serialized
terms, and Glaurung's 34-table SQLite KB are queryable per-function fact stores. And Glaurung already has
the right *shape* for identity: a `function_identity(binary_id, entry_va, scheme, identity, n_blocks,
set_at)` table keyed by `scheme`, with `glaurung-structural-v1` today and WARP GUIDs explicitly
anticipated as another `scheme` value. The recommendation below is an extension of that design, not a
replacement.

### (b) Recommended canonical function representation: the CFR (Canonical Function Representation)

**Define the CFR as a labeled, block-order-independent graph over LLIR-SSA, plus a typed interface
record.** Concretely, three artifacts computed together and versioned together:

**CFR-G: the operator-typed SSA dataflow graph.**
Nodes are SSA values; edges are def→use. Each node's label is a tuple, *not* a name:

```
(op_kind, result_width_bytes, operand_arity, value_class)
value_class ∈ {const, global_addr, stack_addr, function_input, phi, derived}
```

This is BSim's varnode seed, restated in Glaurung's vocabulary: it takes width, defining operation,
constant-ness, and input/global status, and nothing else. Refine with **k=3 iterations of 1-dimensional
Weisfeiler–Leman**, mixing input-neighbour labels — **commutatively for commutative operators**
(`Add`, `Mul`, `And`, `Or`, `Xor`, `Eq`, `Ne`, and phi) and **positionally for the rest** (`Sub`, `Div`,
`Shl`, `Shr`, `Sar`, `Ult`, `Slt`, `Load` address vs value, `Store` address vs value). Drop shadow nodes:
pure `Assign` copies and phis whose incoming values are all the same. Three iterations and commutative
mixing are exactly what BSim does, and they are the reason BSim's features survive instruction scheduling
and operand reordering.

**CFR-C: the block-order-independent CFG labeling.**
Seed each block with `(in_degree << 8) | out_degree` — BSim's seed, and the only block label in the field
that is independent of address, size and layout. One WL iteration mixing predecessor labels
commutatively, with distinct mixing constants for taken/fallthrough edges. Store the edge multiset with
edge kinds `{cond_true, cond_false, unconditional, switch}` and a precomputed **`is_back_edge`** flag from
the existing `structure_v2::dominators` (BinExport2 stores exactly this, computed by Lengauer–Tarjan).
Fuse CFR-G node labels into CFR-C at each *root* op — `Call`, `IndirectCall`, `Store`, `CondJump`,
`Return` — which is the BSim "BlockSignature" construction and is what keeps topology and semantics in the
same feature.

**CFR-I: the typed interface record.** Return type; parameters keyed by **ABI position**; locals keyed by
**frame offset**; callee set; the boolean effect summary Glaurung's `effect_census` already computes. Keys
are storage locations, never names — this is what DecBench matches on and what rev.ng's
`RawFunctionDefinition` encodes.

**The mask list, and the justification for each item.**

| Masked | Kept in its place | Precedent |
|---|---|---|
| Register names / allocation | operand *width* and value class | BSim ("names of registers … not incorporated"); Diaphora `mov R R`; MLIL "registers translated to variables" |
| Block layout order | sorted / degree-seeded labels; edge multiset | WARP sorts block GUIDs by address; Glaurung's own fingerprint already sorts blocks; BinDiff MD index |
| Absolute addresses and relocation targets | `is_relocation` bit; call *edge* to a resolved callee identity | WARP zeroes relocatable instructions; BinExport2 `Expression.is_relocation`; FID excludes address-like constants |
| NOPs and alignment padding | nothing | WARP excludes NOPs; Glaurung's fingerprint already does |
| Hot-patch `mov edi,edi`-style self-moves | nothing (arch-conditional) | WARP, with the explicit x86 vs x86-64 caveat |
| Dead flag computations | the *fused* comparison at the branch | BSim `normalize`; LLIL "folds flags into conditional instructions"; GDSL/RREIL reports ~50% code reduction from block-scope flag liveness |
| Stack-frame mechanics (prologue/epilogue, sp arithmetic) | locals keyed by frame offset | BSim "abstracting stack mechanics"; MLIL "the stack as a concept is not present" |
| Large constants and absolute immediates | a bucketed constant class in the label; exact values in a **sidecar multiset** | BSim excludes constant values; FID's full hash excludes them; SAFE masks `|v| > 5000` to `IMM`; PalmTree masks ≥5 hex digits; angr's bindiff demotes constant differences to `ConstantChange` |
| *Not* masked: small constants and stack displacements | kept as label content | SAFE keeps `[EBP-8]` deliberately; PalmTree keeps constants under 4 hex digits — they identify locals, arguments and struct fields |
| *Not* masked: operand position for non-commutative ops | positional mixing in the WL round | ProGraML gives every data edge a `position` encoding operand order; BSim mixes non-commutative inputs positionally |
| Callee *identity* for internal calls; kept for external | call edge to a resolved identity; external symbol name kept | jTrans maps internal call names to `<function>` and keeps external ones — stable interfaces survive versions, internal ones do not |
| Varnode size differences at ≥4 bytes (optional mode) | width class `{1,2,>=4}` | BSim `medium_nosize`, which is what enables 32↔64-bit matching |
| Type *names* | type *structure* (kind × size × pointee) | BSim excludes data types; rev.ng separates structural `Type` from named `TypeDefinition` |
| Symbol names | separately, in the payload | WARP separates GUID from `Symbol`/`Type` payload |

**Determinism and serialization requirements.** Compute over a canonical iteration order (blocks sorted by
entry VA before hashing, operands sorted for commutative ops, feature multiset sorted by hash value).
Serialize the feature vector as a sorted `(u32 hash, u16 count)` list — BSim's `1:545c6155` encoding —
which makes cosine similarity an O(n+m) merge join. Emit a single hex digest as the `identity` for the
existing `function_identity` table, and version the whole thing as
`scheme = "glaurung-cfr-v1"` with an explicit `(major, minor, settings)` triple stored in `schema_meta`,
following BSim's `DatabaseInformation.major/minor/settings`. **Any change to the mask list invalidates
every stored vector**; the version field is not optional.

### (c) Per-function fact schema for BinExport/BSim-comparable export

A single `function_facts` view, whose fields are the intersection identified in §7.6, expressible as three
new KB tables alongside the existing 34 (all keyed `(binary_id, entry_va)`):

```
function_signature
  binary_id, entry_va, scheme, cfr_version,
  cfr_digest TEXT,            -- CFR identity, feeds function_identity(scheme,identity)
  feature_vector BLOB,        -- sorted (u32 hash, u16 count) pairs
  n_blocks, n_edges, n_calls, n_indirect_calls, n_loads, n_stores, n_returns,
  cyclomatic, n_loops, n_sccs, max_loop_depth,
  md_index_topdown REAL, md_index_bottomup REAL,   -- BinDiff-comparable
  op_multiset_spp TEXT,       -- small-primes product over LLIR opcodes (Diaphora-comparable)
  warp_function_guid TEXT,    -- WARP-comparable, own scheme row
  set_at

function_interface
  binary_id, entry_va,
  return_type_id, calling_convention, is_variadic,
  params_json,   -- [{abi_position, storage, type_id, name?}]
  locals_json,   -- [{frame_offset, size, type_id, name?}]
  callee_ids_json, caller_ids_json, adjacent_ids_json,   -- WARP-style constraints
  effects_json   -- reads_mem, writes_mem, may_throw, noreturn, ...

function_evidence
  binary_id, entry_va,
  constants_json, string_refs_json, global_refs_json, imports_json
```

Plus a program-level `export_meta(executable_id, md5, sha256, architecture, compiler, os, abi,
cfr_version, exporter_version)` mirroring BSim's `ExecutableRecord` and BinExport2's `Meta`.

The mapping to the two interchange targets is then mechanical:

- **→ BinExport2**: `function_signature` + CFG → `CallGraph.Vertex` (`address`, `type`, `mangled_name`,
  `demangled_name`) and `FlowGraph` (`basic_block_index[]`, `entry_basic_block_index`,
  `Edge{source, target, type, is_back_edge}`); Glaurung's `memory_operand_facts` → `Operand`/`Expression`
  trees with `is_relocation`; interning is already the KB's habit. Glaurung would then be BinDiff- and
  VxSig-consumable, and its results directly comparable to IDA's and Ghidra's on the same binary.
- **→ BSim-comparable**: `feature_vector` + `function_interface` map onto `SignatureRecord` +
  `FunctionDescription(function_name, address, sigrec, callrec, flags)` + `ExecutableRecord`. Ghidra's
  interchange format from `generatesigs` is XML, so an XML emitter is a small piece of work if
  cross-tool comparison against a Ghidra BSim corpus is wanted.
- **→ WARP**: a FlatBuffers `Function{guid, symbol, type, constraints, comments, variables}` writer.
  The schema is small and stable and the format is Apache-2.0; this is the cheapest real
  interoperability win available.

### (d) Ranked recommendations with effort estimates

1. **Promote the structural fingerprint from disassembly to LLIR-SSA (CFR-G + CFR-C). ~3-5 weeks.**
   `structural_fingerprint.py` today tokenizes *disassembly* and is therefore still sensitive to
   instruction selection, scheduling, and the choice of equivalent encodings — the exact things -O0/-O2
   and cross-compiler comparison change. BSim, MLIL-SSA, and every ACFG-family result operate one level
   up. Glaurung already has SSA (`value_number`), copy propagation, dominators (`structure_v2`), and a
   CFG; the missing work is the WL labeling, the commutativity table over `BinOp`/`CmpOp`, shadow-node
   elimination, and — the one real prerequisite — **making `Width` derivable for `VReg::Temp`**.
   Ship it as `scheme = "glaurung-cfr-v1"` in the existing `function_identity` table; the old scheme keeps
   working, and the two can be A/B'd on the same corpus.

2. **Adopt the WARP function GUID as a second identity scheme. ~1 week.**
   Apache-2.0, fully specified in the README, deliberately cross-tool, and Glaurung's own design doc
   already names it. It is byte-level and therefore *weaker* than the CFR, but it is the only scheme in
   the survey that makes Glaurung's function identities directly comparable to another tool's. The three
   masking rules (zero relocatable instructions, drop NOPs, drop effectively-NOP self-moves with the
   arch-conditional caveat) are small; the FlatBuffers writer is generated.

3. **Write the `function_signature` / `function_interface` / `function_evidence` tables and a
   BinExport2 emitter. ~3-4 weeks.**
   This is what makes measurement *well-defined and external*: BinDiff becomes a check on Glaurung's own
   diff, and the field's published numbers become reproducible on Glaurung's output. The proto is
   Apache-2.0 and index-addressed, which fits an interned KB well.

4. **Version the canonical form explicitly. ~2 days.**
   `schema_meta` gains `(cfr_major, cfr_minor, cfr_settings)`, and every stored vector records the version
   it was computed under. BSim does this because it had to. Adding it after the first corpus exists is
   painful; adding it now is trivial. Include a `nosize` setting (collapse widths ≥4) from day one — it is
   the single switch that buys 32↔64-bit matching.

5. **Add MD index (top-down and bottom-up) and a small-primes-product opcode multiset. ~1 week.**
   Cheap, well-established, and they give a *pre-filter* that makes CFR comparison tractable at corpus
   scale, plus direct comparability to BinDiff and Diaphora scores.

6. **Adopt DecBench's measurement discipline internally. ~1-2 weeks.**
   Its three metrics — CFG graph edit distance with node labels ignored, types matched by ABI position and
   frame offset, byte-match recompilability — are precisely a *measurement* over the CFR-C and CFR-I
   halves of this proposal. Glaurung's fixture harness already does execution differentials; adding a
   label-free CFG GED against the source CFG closes the gap the project's own notes call out ("execution
   differential is blind to structure").

7. **Add an unsound local peephole normalizer before CFR hashing. ~1-2 weeks.**
   VexIR2Vec's VexINE is the template, and its rules are ones Glaurung already implements for rendering:
   copy propagation, constant folding, CSE, redundant/dead-store elimination — but applied *for
   canonicalization only*, over straight-line peepholes, with the invariant that values used-but-not-
   defined in a peephole are parameters and survive. Also collapse same-semantics opcodes and mask operand
   widths below the label's width class. **This must be a separate artifact from the decompiler IR**: it is
   deliberately unsound, and the field says so out loud ("soundness is not important in this context").

8. **Do not build an e-graph canonicalizer yet. (See §8.)** There is a genuine published gap — nobody has
   applied equality saturation to lifted binary IR — but Cranelift's measured 1.13 e-nodes per e-class
   after rewriting suggests limited algebraic variation to recover, and `egg`'s extraction cost functions
   (`AstSize`, `AstDepth`) are not obviously the right canonical-representative choice for similarity.
   Revisit only if measurement shows algebraic variation (`x*2` vs `x<<1`, `x+(-c)` vs `x-c`, De Morgan
   variants) is a material source of CFR mismatch after recommendation 7. Measure first.

9. **Do not switch IRs.** Nothing in this survey argues for replacing LLIR with p-code, VEX, or LLVM.
   Glaurung's `Op` set is already p-code-shaped, and the frameworks that matter for measurement (BSim,
   BinDiff, WARP, the ACFG family) all compute over properties Glaurung's LLIR-SSA already has. The
   leverage is entirely in the *canonical projection*, not in the IR.

**A note on where SLEIGH and Sail fit.** They are not on the measurement path, but they are the only route
to *trustworthy* lifting: a canonical form is only as sound as the semantics beneath it, and a lifter bug
is indistinguishable from a real difference. If a validation lane is ever wanted, differential testing of
Glaurung's LLIR against `sail-riscv` (BSD-2-Clause, the official RISC-V model) or against p-code via a
SLEIGH binding is the established technique. That is a separate, larger project.


---

## Verification notes

93 distinct URLs, all from a fetch, a search result, or a shallow clone. Schemas quoted as field lists
were read from primary source, not prose: BSim's records from `ghidra/Ghidra/Features/BSim/.../description/`,
WARP's from `warp/rust/src/signature/*.rs` and `signature.fbs`, Diaphora's from `db_support/schema.py`,
angr's bindiff attributes from `angr/analyses/bindiff.py`, BinExport2's from `binexport2.proto`, SARIF's
from `sarif-schema-2.1.0.json`, and Glaurung's own `function_identity` / LLIR types from the working tree.

Explicitly **UNVERIFIED**: that `.bndb` is SQLite-backed; RetDec's registers-as-LLVM-globals lowering (its
design wiki errors out); the SPDX identifier for GDSL (BSD-style 3-clause text, GitHub reports
NOASSERTION); licenses for `sail-arm`, `asl_to_sail`, and DeepSemantic; the internal format of a `.fidb`.
Explicitly **resolved as non-existent**: "sigma normalization" is not a term of art in this literature —
the nearest referent is Genius's attribute set Σ. The [SAFE repo](https://github.com/gadiluna/SAFE)
`LICENSE` grants no rights, which is a finding rather than an omission.

Length note: this report runs long against the 2,500-4,000 word brief. The overage is entirely field
lists, schema tables and rule enumerations — the material the brief asked to be captured exactly. Prose
was compressed twice; the evidence was not cut.
