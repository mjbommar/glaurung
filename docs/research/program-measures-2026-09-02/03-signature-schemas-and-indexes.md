# Function Identity: Signature Schemas and Similarity Indexes

Survey for Glaurung, 2026-09-02. Every URL came from a fetch or search result; every
crate claim was checked against the crates.io JSON API. Unverified items are marked.

**Glaurung's baseline (verified in-tree).** `function_identity(binary_id, entry_va,
scheme, identity TEXT, n_blocks)`, indexed on `(scheme, identity)`
(`python/glaurung/llm/kb/xref_db.py:84`); one writer, `glaurung-structural-v1`
(`.../structural_fingerprint.py`); a "FLIRT-lite" that is exact 32-byte prologue
equality over a 30-entry JSON library with **no mask field** (`src/flirt/mod.rs`,
`data/sigs/glaurung-base.x86_64.flirt.json`). `Cargo.toml` already has `object` 0.37.3
and `uuid` 1.0 -- but `uuid` carries only feature `v4`; WARP needs `v5`. The
`(scheme, identity)` spine is right; what is missing is masks, a payload/provenance
side, and index tables for the schemes that are not equality.

---

## HALF A -- Schemas and match semantics of existing tools

### IDA FLIRT

`.pat` is ASCII, `.sig` the compiled trie. One `.pat` line, per `lancelot-flirt`
(https://github.com/williballenthin/lancelot/tree/master/flirt):

```
<32-byte pattern, ".." = variant> <crc_len:2hex> <crc16:4hex> <func_len:4hex> :0000 name ^0041 refname <tail bytes>
```

Record (`FlirtSignature`): `byte_sig_size` u16; `byte_sig` as `Byte(u8) | Wildcard`;
`size_of_bytes_crc16` u8 (max 0xFF); `crc16` u16; `size_of_function` u64 (max 0x8000);
`names: Vec<Symbol>` where Symbol is `Public{offset,name}` / `Local` (`:%04x@`) /
`Reference` (`^%04x`); plus a tail mask.

**Match: four escalating levels** (Hex-Rays, *FLIRT Technology: In-Depth*,
https://docs.hex-rays.com/core/flirt/concepts/ida-f.l.i.r.t.-technology-in-depth).
(1) Trie walk over the masked 32-byte prefix; shared prefixes live in nodes, so
comparisons grow logarithmically with library size. (2) On a leaf collision, CRC16 over
the bytes from offset 32 **up to the first variant byte** -- the length varies per
function and is therefore stored, and is zero when the first variant byte is at 32.
(3) A single offset at which all leaf members differ, stored as `(offset, byte)` -- the
doc's `_tolower`/`_toupper` case at `32+3+0x0C`. (4) Referenced names: the function
whose relocation at offset N resolves to `_toupper` is `_strupr`. Level 4 is
**recursive and multi-pass**; IDA defers and re-runs. Survivors of all four are a
*collision*, resolved by a human editing an `.exc` file.

**Tolerance.** FLIRT tolerates *linking*, not *compilation*. The doc names its own
limits: functions under 4 bytes without external refs are excluded; linker rewrites
(`call far ptr` -> `nop; push cs; call near`) defeat byte comparison;
identical-implementation/different-name pairs (`remove`/`unlink`) are unresolvable in
principle. Signature files are per-compiler, and a `startup` file runs first to decide
*which* file to use.

**Anti-contamination.** The FLAIR preprocessors (`pelf` ELF, `plb` OMF, `pcf` COFF) run
over `.o`/`.a` **before linking**, so the relocation table says exactly which bytes are
variant. That is the whole trick. `.sig` stores "the arrays of bits determining the
changing bytes and the values of the individual bytes", so it "contains no byte from
the original libraries, except for the names" -- a redistribution property worth copying.

**Rust:** `lancelot-flirt` 0.10.0, Apache-2.0, 2026-07-09, 60,948 downloads; parses and
matches both formats. Trap: the crate named `flirt` on crates.io (0.4.1, BSD-3-Clause,
sr.ht) is unrelated.

### IDA Lumina

Per Synacktiv (https://www.synacktiv.com/en/publications/investigating-ida-lumina-feature):
the key is **MD5 over basic blocks with the processor module's `calcrel()` masks
applied** -- FLIRT's masking, hashed instead of trie'd, as
`struct func_sig_t { uint32_t version; qstring signature; }`. Payload is far richer than
FLIRT's: name, prototype, frame layout and stack variables, SP-delta points, per-operand
representations, comments, size. RPC messages `HELO`, `PULL_MD`/`PULL_MD_RESULT`,
`PUSH_MD`/`PUSH_MD_RESULT`; match is exact hash lookup and the server returns a
**"popularity" count**. Transferable: identity and payload are separate, and the
identity carries a crowd count.

### Ghidra FunctionID (.fidb)

`FunctionsTable.java`: `CODE_UNIT_SIZE` short | `FULL_HASH` long **(indexed)** |
`SPECIFIC_HASH_ADDITIONAL_SIZE` byte | `SPECIFIC_HASH` long | `LIBRARY_ID` | `NAME_ID`
**(indexed)** | `ENTRY_POINT` | `DOMAIN_PATH_ID` | `FLAGS` byte. Alongside:
`LibrariesTable` (name/version/**variant**, variant reserved for compiler settings),
`StringsTable`, and `RelationsTable` with
`RelationType{DIRECT_CALL, INTRA_LIBRARY_CALL, INTER_LIBRARY_CALL}` plus a "Superior
Table" for the parent/child graph.

**Masking** (`MessageDigestFidHasher.hash()`): code units in address order, skipping
arch-specific `InstructionSkipper` hits (NOPs, alignment) *without counting them*;
`prototype.getInstructionMask()` applied to raw bytes so only opcode and addressing-mode
bits survive; registers contribute `(reg.getOffset()+7654321)*98777` to **both** digests;
scalars contribute the sentinel `0xfeeddead` to the **full** digest always, and their
real value to the **specific** digest only when not covered by a relocation
(`hasRelocation()` narrows the operand mask to its nonzero byte range and queries
`program.getRelocationTable()`) and either the whole operand is a non-address scalar or
`|v| < 256`. Both digests are 64-bit; `null` below `shortCodeUnitLimit`. Note
`fullCount = codeUnitIndex - callCount` -- **calls are subtracted from size**, so
call-heavy wrappers score low.

**Match** (`help/topics/FunctionID/FunctionID.html`): look up `FULL_HASH`, then score. A
matching instruction with no constant operands = 1.0; calls and NOPs = 0.0; each constant
matching via the specific hash adds 0.67. The score also accumulates **instructions in
any matched child and any matched parent** -- FLIRT's recursive reference idea as a
score. Filter by `Instruction Count Threshold`, keep the highest score, group survivors
by **demangled base name with namespace and leading underscores stripped**; one group =
"Single Match", else "Multiple Match" behind a second threshold. Libraries report
`(Name, Version, Variant)`, dropping fields that could not be disambiguated.

**Tolerance**, quoting the help: identifiable "even if the library is relocated during
linking. Larger changes to the compilation process... will likely prevent successful
searches." Blind to scheduling, register allocation, inlining.

### Ghidra BSim

**Not bytes.** Features are subgraphs of the decompiler's normalized SSA p-code data-flow
graph (`help/topics/BSim/FeatureWeight.html`): variable size, producing operator,
consuming operators, call-site position and parameter count are encoded; names, data
types, storage location and callee identity are **not**. Hence tolerance to "equivalent
machine instructions, storage location, instruction order, many forms of compiler
transformation, even some forms of deliberate obfuscation."

Vector (`src/lshvector/c/lsh.h`): `LSH_ITEM{uint32 hash; uint16 tf; uint16 idf; double
coeff;}` inside `LSHVECTOR{numitems; hashcount; double length; items[]}` -- a sparse
tf-idf-weighted bag of 32-bit feature hashes. Weight schemes are frozen at DB creation
(`lshweights_{32,64,64_32,nosize,cpool}.xml`); `nosize` is blind to 32-vs-64-bit variable
width so it matches across word sizes at a sensitivity cost.

`lshvector_compare` returns `(sim, sig)`: **weighted cosine** (default threshold 0.7) and
a **log-likelihood-ratio confidence** with published calibration -- confidence 10 ~ 1 in
4,000; 26 ~ 1 in 100,000; 43 ~ 1 in 1e6; 93 ~ 1 in 1e9, halving per 4-5 points.
Confidence is bounded by *self-significance*, roughly proportional to size, so a small
function cannot reach high confidence -- the principled version of FID's threshold.

Index: random-hyperplane LSH (SimHash for cosine) with sign vectors from a 16-point
Hadamard/FFT (`binhash.c`), packed into `lsh_k` bits across `lsh_L` bands, exposed as GIN
entries. Shipped configs: **k=17, L=146 for ~1e7 functions; k=19, L=232 for ~1e8**.

```sql
CREATE TABLE vectable(id BIGINT UNIQUE, count INTEGER, vec lshvector);
CREATE INDEX vectable_vec_idx ON vectable USING gin (vec gin_lshvector_ops);
CREATE TABLE desctable (id BIGSERIAL PRIMARY KEY, name_func TEXT, id_exe INTEGER,
                        id_signature BIGINT, flags INTEGER, addr BIGINT);
CREATE TABLE exetable (id SERIAL PRIMARY KEY, md5 TEXT UNIQUE, name_exec TEXT,
   architecture INTEGER, name_compiler INTEGER, ingest_date TIMESTAMPTZ,
   repository INTEGER, path INTEGER);
CREATE TABLE callgraphtable (src BIGINT, dest BIGINT, PRIMARY KEY (src,dest));
```

`vectable.count` means **vectors are deduplicated and refcounted** (`insert_vec` /
`remove_vec`), with `desctable` rows pointing at a shared `id_signature` -- a large win
on library-heavy corpora.

Backends: PostgreSQL (custom C extension built against PG 15.13 source; distro packages
will not work), Elasticsearch, and **H2 for local single-user**:

```sql
CREATE TABLE <vectable>(id SERIAL PRIMARY KEY, count INTEGER, vec_hash BIGINT, vec CLOB);
CREATE UNIQUE INDEX h2_vectable_index ON <vectable> (vec_hash);
```

**There is no LSH index in the H2 backend at all** -- an exact hash key plus a linear
scan over an in-memory `VectorStore`. Ghidra's own answer for the embedded case is brute
force. Strong prior for Glaurung.

### Binary Ninja WARP

FlatBuffers, `file_identifier "WARP"` (https://github.com/Vector35/warp, Apache-2.0,
v1.0.1, commit `c9cfe5b` 2025-11-05). `File{header, chunks}`; `ChunkHeader{version,
type:{Signatures,Types}, compression_type:{None,Zstd}, size, target:Target{architecture,
platform}}`. Per function:

```
struct FunctionGUID{[ubyte:16]}  BasicBlockGUID{...}  ConstraintGUID{...}
table Constraint{guid; offset:long}
table Function{guid; symbol; type; constraints:[Constraint]; comments; variables}
```

**Basic block GUID** = `UUIDv5(ns 0192a178-7a5f-7936-8653-3cbaa7d6afe7, bytes)` after
(1) zeroing every **relocatable instruction** -- one whose operand is a constant pointer
into a mapped region, or computes one with a constant offset (their aarch64 example
`add x1, x1, #0xf10`); (2) dropping NOPs; (3) dropping register-to-self moves that are
effectively NOPs (hot-patch padding) -- arch-sensitive: `mov edi, edi` drops on x86,
**stays** on x86_64 because the write zero-extends. **Function GUID** =
`UUIDv5(ns 0192a179-61ac-7cef-88ed-012296e9492f, concat(bb_guids sorted by address))`.
**Constraint GUID** = `UUIDv5(ns 019701f3-e89c-7afa-9181-371a5e98a576, x)` where x is a
function GUID, symbol name, or u64; a constraint is `(guid, signed offset)` with
`i64::MAX` as the "unrelated" sentinel, encoding callees, callers and adjacent functions
with locality.

**Match:** compute the GUID and look it up. WARP "never prunes functions when added," so
a GUID may map to many records; constraints narrow them, and whether to *require*
constraint matching is the caller's choice. `WARP\Process` builds `.warp` files from
binaries, BNDBs, or `.a`/`.lib`/`.rlib` with automatic cross-file dedup
(https://docs.binary.ninja/guide/warp.html).

Three advantages over FLIRT/SigKit: masking is derived from **analysis** rather than a
relocation table, so it works on firmware; per-block identity lets small functions be
kept; and a match restores prototype, calling convention and variable types. Stated cost:
"the algorithm must be carefully upgraded to ensure that previously generated UUIDs are
no longer valid." Still exact -- it will not cross `-O0`/`-O2`. **Availability:** the
crate is `warp` v1.0.1, Apache-2.0, **in-repo only, not on crates.io** (the crates.io
`warp` is seanmonstar's HTTP framework).

### Binary Ninja SigKit (predecessor)

A FLIRT-shaped trie of (pattern, mask) with masks from the relocation tables of
**unlinked `.o` inside `.a`** -- `.so` is useless because the relocations are gone; the
fallback "heuristically guess[es] masks based on MLIL patterns". Also stores a secondary
disambiguation pattern and call-graph edges: a candidate must have all call sites and
callees match, with optimistic assume-and-verify for cycles and "bridge nodes" for pruned
functions. On disk: magic `BNSG`, version `01`, zlib-compressed flatbuffer, so the matcher
can mmap and seek lazily. Rationale for staying byte-based: IL matching hits graph
isomorphism (https://binary.ninja/2020/03/11/signature-libraries.html).

### Diaphora

SQLite, one file per binary; diffing `ATTACH`es the second and runs cross-database SQL.
The `functions` table has **48 columns**: `nodes, edges, indegree, outdegree,
instructions, cyclomatic_complexity, primes_value, bytes_hash, function_hash,
mnemonics_spp, microcode_spp, pseudocode_primes, clean_assembly, clean_pseudo,
clean_microcode, md_index, kgh_hash, constants, switches, loops, strongly_connected,
tarjan_topological_sort, bytes_sum, ...`. `mnemonics_spp` is the **product** of
per-mnemonic small primes -- order-blind multiset identity, repeated over microcode ops
and AST nodes. `clean_*` is normalized text with immediates rewritten to `0xXXX`, which
carries the cross-optimization tolerance. `md_index` (Dullien & Rolles, SSTIC'05,
https://www.zynamics.com/downloads/bindiffsstic05-1.pdf) embeds each CFG edge's
`(topo_order(src), indeg(src), outdeg(src), indeg(dst), outdeg(dst))` as
`z0 + z1*sqrt2 + z2*sqrt3 + z3*sqrt5 + z4*sqrt7` and sums `1/sqrt(embedding)`, in
`decimal` because float addition is non-associative. `kgh_hash` (Karamitas & Kehagias,
SANER'18) is a small-prime **product** over node types, edges (all treated as
conditional, so it survives branch reordering) and function factors.

Match: ~50 heuristics, each a SQL query with a base ratio. Rarity heuristics use
`HAVING count(*) <= 2` on both sides plus `nodes > 5` -- **a feature is usable as an
identity only when globally rare**. `check_ratio` short-circuits to 1.0 on equal
`bytes_hash`, else takes the max of `SequenceMatcher` ratios over the `clean_*` texts and
AST primes, and *revokes* a 1.0 if the MD-indices differ. `HEUR_FLAG_SAME_CPU` disables
byte and mnemonic heuristics for cross-architecture diffs.

### BinExport / BinDiff

`binexport2.proto` is proto2 built from **top-level parallel arrays with index-based
dedup** -- the header comment says every unique expression, mnemonic, operand, instruction
and basic block is stored once, explicitly to stop obfuscated malware causing
combinatorial blowup. Messages: `Meta`; `Expression{type, symbol, immediate, parent_index,
is_relocation}` forming an operand *tree*; `Operand`; `Mnemonic`; `Instruction{address,
call_target[], mnemonic_index, operand_index[], raw_bytes, comment_index[]}` where
**address is omitted when it equals prev + raw_bytes.size()**; `BasicBlock{IndexRange[]}`;
`FlowGraph` (edge type + `is_back_edge`); `CallGraph{Vertex, Edge}`; `DataReference`;
`Comment`; `Section`; `MDIndex`.

BinDiff consumes only `raw_bytes` (SDBM-hashed per block and function), the mnemonic
*string* (Goedel-numbered by `GetPrime` and **summed** per block -- weaker than
Diaphora's product, but fits a word), `call_target[]`, and graph topology. 17 function
and 18 basic-block passes, each with a confidence in `bindiff.json`: `name hash matching`
1.0, `hash matching` 1.0, `edges flowgraph MD index` 1.0, `edges callgraph MD index` 0.9,
`prime signature matching` 0.9, `relaxed MD index` 0.7, `string references` 0.7,
`loop count` 0.6, `instruction count` 0.4, `call sequence matching(exact)` 0.1. Each pass
buckets unmatched items by a key and accepts **only 1:1 collisions**, deferring ambiguity
to a weaker pass; name-hash uses the **demangled** name so it survives a compiler change.
Similarity = `0.55*edge_ratio + 0.30*bb_ratio + 0.15*insn_ratio`, averaged with
`1 - |md1-md2|/(1+md1+md2)`, times confidence.

BinDiff's result SQLite is a model worth copying: `function(id, address1, name1, address2,
name2, similarity, confidence, flags, algorithm, ...)` with lookup tables
`functionalgorithm(id,name)` / `basicblockalgorithm(id,name)` -- **the winning algorithm
is stored per match**, the provenance field most schemas omit.

### radare2 zignatures, capa, angr, ghidriff, Nucleus

**Rizin no longer has zignatures** -- `librz/sign/` is FLIRT-only. The radare2 record is
`RSignItem{name, bytes:RSignBytes{size,bytes,mask}, graph:RSignGraph{cc, nbbs, edges,
ebbs, bbsum}, refs[], xrefs[], collisions[], vars[], hash:RSignHash{bbhash}}`, stored as
SDB key/value with `|`-separated `type:payload` tags. `bbhash` is SHA-256 over
basic-block bytes **sorted by address**; the mask (`r_anal_mask`) zeroes bytes after the
opcode prefix of any instruction with `op->ptr` or `op->jump` set -- FLIRT's trick derived
from analysis. Byte match is all-or-nothing masked memcmp graded only by
`min_size/max_size`; graph match is the mean of five `min/max` ratios. Five small integers
collide massively across a stdlib, hence the explicit `collisions` field.

**capa** is a schema for *facts*: `MatchedRule, Characteristic, String, Substring, Regex,
Bytes, Class, Namespace, Arch, OS, Format, API, Property(READ/WRITE), Number, Offset,
Mnemonic, OperandNumber, OperandOffset, Export, Import, Section, FunctionName,
BasicBlock`, over scopes forming a lattice with **upward inheritance** (instruction <
basic block < function; call < span-of-calls < thread < process). Two transferable ideas:
the freeze format splits *the function a fact belongs to* from *the address it was
observed at*, and every address carries an `AddressType` tag.

**angr's bindiff** uses only `(n_basic_blocks, n_edges, n_subfunction_calls)` per
function, seeded by exact names and unique string xrefs then expanded along the call
graph. Three integers collide massively, which is why so much seeding is needed.

**ghidriff** does **not** use FunctionID; it reimplements Ghidra's `FunctionHasher` and
optionally seeds BSim. Hashers (each `MIN_FUNC_LEN = 10`) include
`hash((nbbs, ncalls, nedges))`, `hash(tuple(sorted(instructions)))`,
`hash((sorted(called), sorted(calling), sig))`, plus string-ref and switch hashers. The
**pass order is fixed and each round subtracts its accepted matches**: exact bytes ->
exact instructions -> structural exact -> exact mnemonics -> BSim -> bulk instructions ->
sig/calling/called -> strings -> switch -> two `one_to_many` rounds the code itself warns
admit false negatives. A `modified` entry is `{old, new, diff, diff_type[], ratio,
i_ratio, m_ratio, b_ratio, match_types[]}` -- four SequenceMatcher ratios over decompiled
code, instructions, mnemonics and blocks.

**Nucleus** (Andriesse et al., EuroS&P'17) matters for two schema consequences: a
function is a **set of basic-block ranges**, not an interval, and it may have **multiple
entry points**.

---

## HALF B -- Index structures for Rust, in or beside SQLite

**MinHash + LSH banding** (Broder SEQUENCES'97; MMDS ch.3,
http://infolab.stanford.edu/~ullman/mmds/ch3n.pdf). `b` bands of `r` rows; candidate
probability `1-(1-s^r)^b`, knee at `(1/b)^(1/r)`. Variance `J(1-J)/k`, so SE <=
`0.5/sqrt(k)`: k=128 -> 0.044, k=256 -> 0.031, and +/-0.05 at 95% needs k ~ 384.
Deterministic iff the k seeds are fixed constants, never a `RandomState`. **Best SQLite
fit in the survey**: `(band_idx, band_hash, fn_key)` with a covering PK makes candidate
generation b B-tree seeks.

**b-bit MinHash** (Li & Konig, arXiv:0910.3349) keeps the low b bits and corrects the
collision probability to `C1,b + (1-C2,b)*J`; the constants depend on both set sizes, so
**the schema must carry `|S|` per row**. b=1 is best when set/universe ratios are near 1,
and for small ratios once J >= 0.4; at J=0.5 variance rises at most 3x so k must triple
-- still a **21.3x storage win over b=64**. k=128, b=1 is **16 bytes per function**.

**One Permutation Hashing** (Li/Owen/Zhang NIPS'12) is O(d+k) in one pass, but empty bins
break the LSH property outright -- Shrivastava (arXiv:1703.04664) states OPH "cannot be
used as an LSH" and the naive fix "leads to a significant bias". Optimal densification
reassigns through a 2-universal `h_univ(bin, attempt)` and proves
`Var(h*) <= Var(h+) <= Var(h)`. Crate: `probminhash` 0.1.12 (MIT/Apache-2.0, 2025-06-11).

**SimHash** (Charikar STOC'02): `Pr[h_r(u)=h_r(v)] = 1 - theta/pi`. Manku et al. WWW'07
give the table-permutation trick for "Hamming <= k" -- t sorted copies under different bit
permutations, binary-searching the top `p_i` bits (f=64, k=3: 20 tables at `p_i` 31-33 and
~8 hits/probe, down to 4 tables at `p_i`=16 and ~256K hits). Each permuted view is an
INTEGER column with a B-tree index, so a leading-bit probe is a native range scan.
**SimHash measures cosine over weighted vectors; MinHash measures Jaccard over sets** --
Shrivastava & Li (arXiv:1407.4416) prove `S^2 <= J <= S/(2-S)` and conclude MinHash
"virtually always outperforms SimHash when the data are binary". BSim uses hyperplanes
because its features *are* tf-idf weighted.

**Exact Jaccard joins.** For threshold t the indexing prefix length is
**`|x| - ceil(t*|x|) + 1`** and the length filter **`t*|x| <= |y| <= |x|/t`** (PPJoin
Alg.1 line 5, https://www.cse.unsw.edu.au/~lxue/WWW08.pdf; Mann et al. Table 1,
https://www.vldb.org/pvldb/vol9/p636-mann.pdf). AllPairs = prefix + length + an index
storing only prefixes. The empirical verdict matters more than the algorithms:
Mann/Augsten/Bouros (PVLDB 9(9) 2016) found "the plain application of the prefix-filter
in AllPairs is still competitive... whereas complex techniques like PPJoin+ and AdaptJoin
are rarely competitive". **Build AllPairs; do not build PPJoin+.**

**TLSH** (Oliver/Cheng/Chen ACSW'13): 5-byte sliding window, 6 of 10 triplets,
Pearson-hashed into 128 buckets, quartiles; **3-byte header** (checksum, log-length,
packed `q1*100/q3 mod 16` and `q2*100/q3 mod 16`) + **32-byte body** (2 bits/bucket).
Distance sums header and body terms; per nibble-pair `d=|x-y|` except **d==3 scores 6**,
and header mismatches beyond 1 multiply by 12. Calibration: **<30 -> 0.0018% FP / 32.2%
detection; <50 -> 0.52% / 65.3%; <100 -> 6.43% / 94.5%**. Minimum input **50 bytes plus
real entropy** -- "a byte stream of identical bytes will not generate a hash value".
HAC-T indexes with a **vantage-point tree** (observed O(log N)), single-linkage at radius
10-50. Deterministic, no seed. Crate **`tlsh2` 1.1.0** (Apache-2.0 OR BSD-3-Clause,
2025-10-12): pure Rust, `no_std`, streaming.

**ssdeep/CTPH** (Kornblum DFRWS'06): a rolling hash over a 7-byte window emits a base64
char from FNV's low 6 bits; a second FNV runs at `2b`, and **only signatures whose block
sizes are within a factor of 2 can be compared.** The small-input failure is structural --
with `S*b_min = 192`, short inputs land on `b=3` and the signature is information-free;
ssdeep's own docs say files should contain **at least 4 KB**. Raff & Nicholas
(arXiv:1708.03346) add that "ssdeep is sensitive to byte ordering, which is a weakness for
formats that support arbitrary re-ordering of contents (such as **binary executable
files**)", and that changing 0.005% of a file drops the score below 70. **This is the
file-vs-function granularity distinction**: keep Glaurung's CTPH for files, never extend
it to functions. (`ssdeep` 0.7.0 is a GPL-3.0 C wrapper; `fuzzyhash` 0.2.2 is pure-Rust
MIT but unreleased since 2023-03.)

**Membership filters** (Graf & Lemire, arXiv:1912.08258, arXiv:2201.01174). Measured on
1e6 keys with `xorf` 0.13.0 (MIT, 2026-08-21), release build: **BinaryFuse8 = 9.044
bits/key, 0.390% FPR, 31.8 ms build; Xor8 = 9.840 bits/key, 81.5 ms; BinaryFuse16 =
18.088 bits/key, 0.00165% FPR**; lookup ~3.4 ns. Bloom at the same FPR needs ~11.4
bits/key. At 1e7 identities BinaryFuse8 is **11.3 MB** -- one SQLite BLOB, and `xorf`
ships `BinaryFuse8Ref<'a>` for zero-copy reads off an mmap. **Two measured determinism
traps:** `xorf`'s default `uniform-random` feature fills unused slots with entropy, so
two builds over identical keys produced *different bytes* (fix:
`default-features = false, features = ["binary-fuse","serde"]`, byte-identical at
unchanged FPR); and `fastbloom` 0.17.0 hashes with "SipHash-1-3 using randomized keys" by
default. Construction **fails on duplicate keys**, and `bincode` 1.3 cannot serialize the
filter -- Glaurung is already on bincode 2.

**ANN.**

| Crate | Version / date | License | Persistence | Deterministic |
|---|---|---|---|---|
| `hnsw_rs` | 0.3.4, 2026-02-28 | MIT/Apache-2.0 | dump/reload + mmap | **serial `insert()` yes** (hard-coded seed 397); `parallel_insert` no |
| `usearch` | 2.26.2, 2026-08-31 | Apache-2.0 | single-file `view()` mmap | UNVERIFIED |
| `instant-distance` | 0.6.1, 2023-06-26 | MIT/Apache-2.0 | serde, in-memory | **no, despite `Builder::seed`** |
| `faiss` (Enet4) | 0.13.0, 2025-11-15 | MIT/Apache-2.0 | write/read_index | pinned to Faiss 1.7.2 vs upstream 1.15.0 |
| `hora` / `granne` / `annoy*` | 2021 or earlier | -- | -- | abandoned |

`instant-distance` is the sharp one: six rebuilds with identical seed and insertion order
disagreed (10 of 10 results flipped), and `RAYON_NUM_THREADS=1` made them byte-identical
-- the nondeterminism is the rayon construction loop, not the seed. **There is no
maintained standalone pure-Rust PQ/IVF crate**; the only real one is inside `lance-index`
11.0.0. HNSW memory is roughly `M*8-10` bytes per element on top of the vectors, `M`
12-48 typical. **Flat wins under ~1e6 vectors**: exactly deterministic, zero build, zero
index bytes, arbitrary filtering. 1e6 x 128-d f32 is 512 MB and ~50 ms single-threaded
(estimate); binary 256-bit codes at 1e7 are 320 MB and popcount in ~32 ms -- which is
what Ghidra's embedded BSim backend does.

**SQLite vector extensions.** `sqlite-vec` (Apache-2.0 + MIT) is **still pre-1.0 and says
so**; last stable v0.1.9 (2026-03-31), newest `v0.1.10-alpha.4`, and **the repo has not
been pushed since 2026-05-18**. `vec0` creates shadow tables `_chunks / _rowids /
_vector_chunksNN / _auxiliary / _metadatachunksNN`, default chunk_size 1024, element
types FLOAT32/BIT/INT8. **ANN has not shipped**: the query-plan enum on `main` is still
`FULLSCAN|POINT|KNN`, KNN is a brute-force chunk scan, and DiskANN/IVF sources sit behind
`SQLITE_VEC_ENABLE_DISKANN` / `SQLITE_VEC_EXPERIMENTAL_IVF_ENABLE` -- while **the Rust
crate's `build.rs` is one line that defines neither**. `sqlite-vss` is dead by its own
README (last push 2024-05-05).

**Inverted indexes.** `tantivy` 0.26.1 (MIT, 2026-04-21) supports unscored retrieval --
`TermSetQuery` plus `ConstScoreQuery`, which explicitly "avoid[s] unnecessary score
computation" -- but costs a second on-disk store with its own commit and merge lifecycle,
and BM25 scores shift as segments merge. **SQLite FTS5 is the better fit**: store
pre-normalized n-grams space-joined in a contentless (`content=''`) table with
**`detail=none`** and the `ascii` tokenizer, and query with boolean `MATCH` -- no ranking
unless you `ORDER BY rank`/`bm25()`, so retrieval is a deterministic postings
intersection. SQLite's own measurement on a 1636 MiB corpus: 743 MiB at `detail=full`,
340 MiB at `column`, **134 MiB at `none`**. The FTS5 `trigram` tokenizer landed in SQLite
3.34.0 (2020-12-01).

**Cost per function** (arithmetic unless noted): BinaryFuse8 gate 1.13 B (measured);
b-bit MinHash k=128 b=1 **16 B**; PQ m=16 24 B; binary 256-bit 32 B; TLSH 35 B; f32 d=128
512 B; HNSW graph +128-160 B. Sparse postings at ~100 tokens/function: 150-300 MB at 1e6.

---

## SYNTHESIS

### (1) Proposed SQLite schema

Full DDL with commentary is in `03-schema.sql` beside this file. Core:

```sql
-- Existing table holds every EXACT scheme. Match = equality on (scheme, identity).
-- Schemes: 'glaurung-structural-v1', 'warp-function-guid-v1', 'fid-full-hash-v1',
--          'fid-specific-hash-v1', 'lumina-md5-v1'.
ALTER TABLE function_identity ADD COLUMN n_units INTEGER;  -- code units, calls excluded
ALTER TABLE function_identity ADD COLUMN n_bytes INTEGER;

-- Provenance: Ghidra FID's LibrariesTable + WARP's Target.
CREATE TABLE siglib (
    siglib_id INTEGER PRIMARY KEY, name TEXT NOT NULL, version TEXT,
    variant TEXT,                      -- compiler settings; FID reserves this field
    architecture TEXT NOT NULL, platform TEXT, source_sha256 TEXT, ingest_date INTEGER,
    UNIQUE (name, version, variant, architecture, platform));

-- What we match AGAINST. Deduplicated like BSim's vectable; `occurrences` is Lumina's
-- "popularity" and the cheapest false-positive signal available.
CREATE TABLE siglib_function (
    sigfn_id INTEGER PRIMARY KEY, siglib_id INTEGER NOT NULL REFERENCES siglib,
    scheme TEXT NOT NULL, identity TEXT NOT NULL, name TEXT NOT NULL,
    base_name TEXT,                    -- demangled, namespace+underscores stripped:
                                       -- exactly what FID groups Multiple Matches on
    n_units INTEGER, n_bytes INTEGER, prototype TEXT,
    payload BLOB,                      -- CBOR: comments, stack vars, calling convention
    occurrences INTEGER NOT NULL DEFAULT 1,
    UNIQUE (siglib_id, scheme, identity, name));
CREATE INDEX idx_siglib_function_lookup ON siglib_function(scheme, identity);

-- FLIRT-style MASKED signatures. Cannot live in `identity TEXT`: matching is a masked
-- walk, not equality.
CREATE TABLE siglib_flirt (
    sigfn_id INTEGER PRIMARY KEY REFERENCES siglib_function,
    pattern_len INTEGER NOT NULL,      -- normally 32
    pattern BLOB NOT NULL,             -- masked positions stored as 0x00
    mask BLOB NOT NULL,                -- 1 bit/byte, MSB-first; 1 = fixed
    prefix_key BLOB NOT NULL,          -- pattern[0..8], masked bytes zeroed
    prefix_key_mask INTEGER NOT NULL,  -- those 8 mask bits, so 0x00 != wildcard
    crc_len INTEGER NOT NULL, crc16 INTEGER NOT NULL, func_len INTEGER,
    tail_offset INTEGER, tail_byte INTEGER);
CREATE INDEX idx_siglib_flirt_prefix ON siglib_flirt(prefix_key, prefix_key_mask);

-- FLIRT `^offset name` refs, WARP constraints and FID parent/child are one shape.
CREATE TABLE siglib_reference (
    sigfn_id INTEGER NOT NULL REFERENCES siglib_function,
    kind TEXT NOT NULL,                -- flirt-ref | warp-call | warp-adj | fid-child
    offset INTEGER NOT NULL,           -- signed; WARP uses i64::MAX for "unrelated"
    referent_name TEXT, referent_guid TEXT,
    PRIMARY KEY (sigfn_id, kind, offset, referent_name, referent_guid));

-- BSim-style sparse weighted vectors, deduplicated and refcounted as BSim does.
CREATE TABLE feature_vector (
    vector_id INTEGER PRIMARY KEY, vector_hash INTEGER NOT NULL UNIQUE,
    n_features INTEGER NOT NULL, norm REAL NOT NULL,
    weights_id TEXT NOT NULL,          -- '32'|'64'|'64_32'|'nosize'; frozen per corpus
    features BLOB NOT NULL,            -- {u32 hash, u16 tf, u16 idf} LE, sorted by hash
    refcount INTEGER NOT NULL DEFAULT 1);
CREATE TABLE function_vector (binary_id INTEGER, entry_va INTEGER,
    vector_id INTEGER REFERENCES feature_vector, PRIMARY KEY (binary_id, entry_va));
CREATE TABLE feature_weight (weights_id TEXT, feature_hash INTEGER,
    doc_count INTEGER NOT NULL, weight REAL NOT NULL,
    PRIMARY KEY (weights_id, feature_hash));
CREATE TABLE vector_band (          -- BSim's lsh_k/lsh_L as rows. SKIP below ~1e5.
    band_idx INTEGER, band_hash INTEGER, vector_id INTEGER REFERENCES feature_vector,
    PRIMARY KEY (band_idx, band_hash, vector_id)) WITHOUT ROWID;

-- Jaccard token sets. token_ord is ASCENDING corpus frequency, so a prefix is the
-- rarest tokens -- that is what makes prefix filtering work.
CREATE TABLE token_dict (token_id INTEGER PRIMARY KEY, token TEXT UNIQUE,
    doc_count INTEGER NOT NULL, token_ord INTEGER NOT NULL);
CREATE TABLE function_token (fn_key INTEGER, token_id INTEGER, pos INTEGER,
    set_len INTEGER NOT NULL, PRIMARY KEY (fn_key, token_id)) WITHOUT ROWID;
CREATE TABLE token_prefix_index (   -- AllPairs' parsimonious index: prefixes only
    token_id INTEGER, set_len INTEGER, fn_key INTEGER, pos INTEGER,
    PRIMARY KEY (token_id, set_len, fn_key)) WITHOUT ROWID;
CREATE TABLE function_minhash (fn_key INTEGER, params_id TEXT, set_len INTEGER,
    sig BLOB NOT NULL, PRIMARY KEY (fn_key, params_id)) WITHOUT ROWID;
CREATE TABLE minhash_band (params_id TEXT, band_idx INTEGER, band_hash INTEGER,
    fn_key INTEGER, PRIMARY KEY (params_id, band_idx, band_hash, fn_key)) WITHOUT ROWID;

-- TLSH: header columns are the prefilter, body compared in-process.
CREATE TABLE function_tlsh (fn_key INTEGER PRIMARY KEY, lvalue INTEGER,
    q1_ratio INTEGER, q2_ratio INTEGER, body BLOB NOT NULL);
CREATE INDEX idx_function_tlsh_hdr ON function_tlsh(lvalue, q1_ratio, q2_ratio);

-- "Is this in ANY known library?" One binary-fuse filter per (scheme, arch).
CREATE TABLE identity_filter (scheme TEXT, architecture TEXT, kind TEXT,
    n_keys INTEGER, built_at INTEGER, filter BLOB NOT NULL,
    PRIMARY KEY (scheme, architecture));

-- Auditable results. `evidence` records WHICH level resolved it, as BinDiff stores the
-- winning algorithm per match.
CREATE TABLE function_match (binary_id INTEGER, entry_va INTEGER, scheme TEXT,
    sigfn_id INTEGER REFERENCES siglib_function, score REAL, confidence REAL,
    rank INTEGER NOT NULL, ambiguous INTEGER NOT NULL DEFAULT 0,
    evidence TEXT, set_at INTEGER,
    PRIMARY KEY (binary_id, entry_va, scheme, rank));
```

**Match semantics.** *Exact*: equality; ambiguity is surfaced, never guessed -- which
Glaurung's `port_annotations` already does. *FLIRT*: L1 seek on `(prefix_key,
prefix_key_mask)` -- an 8-byte B-tree key does what a trie node does, and SQLite already
has the B-tree -- then verify `pattern & mask == candidate & mask`; L2 CRC16 over
`crc_len` bytes from `pattern_len`; L3 `(tail_offset, tail_byte)`; L4 every
`siglib_reference` row must resolve, recursively and multi-pass. More than one survivor
after L4 is a genuine collision: report all names, pick none. *BSim*: weighted cosine
(0.7) **and** log-likelihood confidence -- report both, because only the confidence
carries a false-positive rate. *Jaccard*: AllPairs prefix + length filter, then exact
verification. *TLSH*: header prefilter, in-process distance, threshold 30 or 50.

### (2) Index per use case

| Use case | Index | Why |
|---|---|---|
| Name stripped binaries from libc / libstdc++ / OpenSSL across compilers and `-O` levels | **Masked FLIRT prefix index + WARP GUID equality**, gated by a BinaryFuse8 filter. **One `siglib` row per (library, version, compiler, flags)**. | No exact or masked scheme crosses an optimization level -- FLIRT, FID, WARP and SigKit all say so. The answer is not a cleverer hash, it is N libraries keyed by `variant`. The gate answers "seen this at all" in 3.4 ns. |
| Rank changed functions between two builds of a ~6000-function kernel | **Exact equality first, then a flat scan** over the residue, ghidriff-style ordered passes each subtracting their matches. | 6000 functions is nothing. Ghidra's own embedded backend scans linearly at this size; an ANN index is pure liability. Store `evidence` per match. |
| Identify statically linked libraries | **`occurrences` + call-graph constraints + rarity gating.** | Diaphora's `HAVING count(*) <= 2` is the operative idea: a feature is an identity only when globally rare. FID's parent/child scoring and WARP's constraints are the same insight. |
| Cluster malware families | **b-bit MinHash banding over normalized token sets, plus TLSH at distance <= 30.** | Jaccard over binary token sets is the right measure (MinHash dominates SimHash on binary data). 16 bytes/function at k=128, b=1. TLSH is an independent, order-tolerant second opinion. |

### (3) Building libraries without relocation contamination

**Use `.a`, never `.so`.** A `.a` holds unlinked `.o` files with full relocation tables;
SigKit: the linker "basically copy-pastes it byte-for-byte... The only bytes that change
are the relocation bytes." FLIRT's preprocessors are named for that input class, and
`WARP\Process` accepts `.a`/`.lib`/`.rlib`. **Glaurung's current builder reads linked
sample binaries** (`source_binary` points at `samples/.../hello-clang-O2`) -- the
contaminated path: with no relocation table every `call rel32` and `lea rip+disp32` is an
absolute that changes on the next link.

Four mask sources, most to least reliable: (1) **relocation table of the `.o`** -- exact;
`object` 0.40.0 reads archive members and `Section::relocations()`, and Glaurung already
depends on `object` 0.37.3. (2) **Relocation table of the linked binary** (FID's
`hasRelocation()`) -- works for PE and PIE ELF, fails for non-PIE and firmware.
(3) **Instruction-prototype masking**, FID's other half -- only opcode and
addressing-mode bits enter the digest and registers enter as offsets, so it needs no
relocations at all. (4) **Semantic detection of relocatable operands**, WARP's approach
and the most portable -- which `structural_fingerprint.py` is already doing in Python
for x86.

Three shared rules: *exclude what you cannot distinguish* (FLIRT drops <4-byte functions
with no refs; FID returns null below `shortCodeUnitLimit`; SigKit prunes but keeps
"bridge nodes"); *do not store library bytes* (split `pattern` from `mask`, as FLIRT does
deliberately for redistribution); and *key the library by (name, version, variant, arch,
platform)* -- a corpus spanning gcc/clang x O0-O3 is not one library, it is N libraries
sharing a name.

### (4) Ranked recommendations

1. **Add masks to the FLIRT-lite, and build libraries from `.a`, not linked samples.**
   The current 32-byte exact-equality matcher cannot match a relinked library at all --
   it is a demo, not a mechanism. Adopt `siglib_flirt` + `siglib_reference`, deriving
   masks from `object`'s archive relocations. *Effort: 3-5 days.* **Price the alternative
   first:** `lancelot-flirt` 0.10.0 (Apache-2.0, actively released) gives `.pat`/`.sig`
   parsing and matching for free, and open libraries exist (`fireeye/siglib`,
   `Maktm/FLIRTDB`). *Effort with the crate: 1-2 days.*
2. **Add `warp-function-guid-v1` as a second `scheme`.** No schema change --
   `function_identity` was designed for it. Needs `uuid` feature `v5` (a one-line
   `Cargo.toml` edit), relocatable-instruction detection (mostly present in
   `structural_fingerprint.py`), and NOP/hot-patch-move filtering. The README is a
   complete spec; the `warp` crate is Apache-2.0 but git-only. *Effort: 1 week for
   x86_64, ~2 days per additional architecture.*
3. **Add the BinaryFuse8 gate.** `xorf` 0.13.0 with `default-features = false` (the
   defaults are non-deterministic, measured), one BLOB per `(scheme, arch)`, read via
   `BinaryFuse8Ref`. 1.13 bytes/key, 3.4 ns/probe, 11.3 MB at 1e7. Cheapest win here.
   *Effort: 1 day.*
4. **Record `siglib` provenance and `function_match` evidence.** The difference between
   "matched `memcpy`" and "matched `memcpy` from glibc 2.39 gcc-13.2 -O2 via FLIRT L2".
   *Effort: 2 days.*
5. **Jaccard token sets with AllPairs.** Exact, deterministic, no tuning, pure SQL over
   `token_prefix_index`. Add b-bit MinHash banding only when the exact join measures too
   slow. *Effort: 3 days exact; +3 for the MinHash lane.*
6. **TLSH via `tlsh2`**, for functions >= 50 bytes with real entropy. *Effort: 1-2 days.*
7. **BSim-style p-code feature vectors** -- highest ceiling, most work: extraction from
   Glaurung's IR, a corpus-derived weight table, and the cosine/confidence pair. Start
   with **no LSH index**: Ghidra's H2 backend has none, and a flat scan over 1e5 vectors
   is milliseconds. Add `vector_band` only past ~1e6. *Effort: 3-6 weeks.*
8. **Do not build:** `sqlite-vec` ANN (compile-gated off; the Rust crate's one-line
   `build.rs` enables neither flag; repo quiet since 2026-05-18), `sqlite-vss` (dead by
   its own README), `faiss-rs` (pinned to Faiss 1.7.2), `instant-distance` (fixed seed
   does not give reproducibility -- measured), PPJoin+ ("rarely competitive"), and CTPH
   at function granularity.

**One schema caveat from Nucleus:** a function can be non-contiguous and can have multiple
entry points, so `entry_va` is a *label*, not a definition. WARP's per-basic-block GUID
construction is compatible with that; a byte-range prologue signature is not.
