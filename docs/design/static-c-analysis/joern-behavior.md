# What Joern does for DecBench, exactly

> **Kind:** design · **Status:** proposed

DecBench's Structural Correctness metric (GED) is the dominant contributor to
Glaurung's DecBench standing — 69 of our 82 published Union points
([`development/decompiler-testing.md`](../../development/decompiler-testing.md)) —
and every one of those points is decided by a JVM program we do not control,
running a C front end we have never characterized. This document characterizes
it: what runs, what it emits, what survives into the number, and what is
measurably lost on the way.

It describes an external system as it is today, not something Glaurung has
built. The requirements lifted from it are
[`requirements.md`](requirements.md); the stage that reproduces it is
[`parity-plan.md`](parity-plan.md); the programme it is one milestone of is
[`roadmap.md`](roadmap.md).

## 0. Where the code is

| component | version | path |
|---|---|---|
| DecBench (fork) | `efc5d5a` | `$DECBENCH_DIR`, defaulted to `/nas4/data/workspace-infosec/decbench` by `scripts/decbench-local-gate.sh` |
| pyjoern | `4.0.150.4` | `$DECBENCH_DIR/.venv/lib/python3.12/site-packages/pyjoern` |
| Joern | `v4.0.150` | `pyjoern/bin/joern-cli` — 105 jars, Scala 3.4.3, 1.9 GB |
| C parser | Eclipse CDT 8.4.0 | `pyjoern/bin/joern-cli/frontends/c2cpg/lib/io.joern.eclipse-cdt-core-8.4.0.202401242025.jar` |
| GED engine | `cfgutils` | `$DECBENCH_DIR/.venv/.../cfgutils/similarity/ged/vujosevic_janicic_ged.py` |

All paths below are relative to one of those three trees. They are quoted as
inline code rather than links because they are outside this repository.

## 1. The pipeline, end to end

Nine stages sit between a C file and a GED number. Only the last two are
DecBench's own; everything from stage 2 to stage 7 is Joern or pyjoern.

```
 1. text normalization       decbench/utils/cfg.py       Python
 2. JVM boot + CPG build     joern --script FastParser   Scala / Eclipse CDT
 3. per-method dotCfg        FastParser.sc               Scala
 4. JSON on stdout           FastParser.sc               delimiters + regex
 5. DOT -> nx.DiGraph        pyjoern/cfg/__init__.py     pygraphviz
 6. JIL lift                 pyjoern/cfg/jil/lifter.py   one Block per DOT node
 7. supergraph + funcend     cfgutils + pyjoern          basic-block coalescing
 8. TU resolution            decbench/utils/cfg.py       which body scores which binary
 9. vj_ged                   cfgutils                    Hungarian assignment
```

Stage 2 is a **fresh JVM per parse**. `pyjoern.parsing.fast_parser._run_fast_parser_scala_script`
builds `joern --script FastParser.sc --param target_dir=<file>` and
`subprocess.run`s it; the `joern` launcher is a shell script that execs a JVM
with `-XX:+UseG1GC -XX:CompressedClassSpaceSize=128m -XX:+UseStringDeduplication`.
There is no server mode in this path and no JPype: one file, one JVM, one CPG,
one process exit.

### 1.1 Stage 1 — text normalization (DecBench, not Joern)

Three pure text passes in `decbench/utils/cfg.py`, and which ones apply depends
on which side is being parsed.

| pass | source side (`.i`) | decompiled side (`.c`) |
|---|---|---|
| `strip_system_headers` | yes | no |
| `sanitize_decompiled_c` | **never** | yes |
| rename to a temp `.c` | yes | yes |

`strip_system_headers` walks the `# <line> "<file>"` markers gcc emits and keeps
only lines whose originating file is not under `/usr/`, not `<built-in>`, and
not `stdc-predef.h`. A `.i` file is 80–98% inlined glibc and toolchain headers;
without this pass Joern either times out or buries the project's own functions
under thousands of header inlines. Because `#ifdef` selection and macro
expansion were already done by the real compiler, what survives is exactly the
code that was compiled.

`sanitize_decompiled_c` rewrites four decompiler-specific quirks that break the
CDT parse, and is applied **only to decompiler output** — sanitizing ground
truth would be wrong:

* `T [N] name(...)` → `T name(...)` (angr/ghidra aggregate return), anchored to
  line start so an in-body `char buf[16];` is never touched;
* `` @ rax`` register annotations stripped (binja);
* `__int128` → `long long` (ida);
* raw control bytes inside string/char literals escaped to `\xNN`.

The last one is not cosmetic. pyjoern's parser reads JSON out of the Scala
script's stdout; one raw `0x1b` from an inlined `.rodata` ANSI sequence makes
that stdout non-JSON, and `_run_fast_parser_scala_script` then raises for the
**whole file** — every function of that binary loses its CFG, not one.

Finally, both sides are copied to `tempfile.mktemp(suffix=".c")` before parsing.
Two reasons: Joern names its workspace after the input basename, so concurrent
parses of same-named files collide; and `importCode` dispatches its front end on
the extension, so a `.i` file must arrive as `.c`.

### 1.2 Stages 2–4 — the CPG and `dotCfg`

`pyjoern/scala/FastParser.sc` does `importCode(target_dir)`, keeps every
`cpg.method` that has both a start and an end line and whose body is not
`<empty>`, and for each emits a JSON record between `PYJOERN_DATA_START` /
`PYJOERN_DATA_END` markers. The record carries `name`, `fullname`, `filename`,
`signature`, line range, `gotos`, `calls`, `control_structures`, `callees`, and
the three graph exports `x.dotCfg`, `x.dotDdg`, `x.dotAst` as DOT strings.
DecBench uses only `cfg`.

**`dotCfg` is expression-granular.** Joern's CFG is not a basic-block graph. It
is a graph over CPG nodes in evaluation order, so a single C statement
contributes many nodes — one per subexpression. Counting the node-type tokens
still visible in the published labels across 120 O0 binaries gives, in order:
`FIELD_IDENTIFIER` (50,376), `<operator>.indirectFieldAccess` (33,005),
`<operator>.indirectIndexAccess` (26,643), `UNKNOWN` (20,444),
`<operator>.cast` (18,357), `<operator>.fieldAccess` (17,131), the method
start/end markers, then the arithmetic, address-of, indirection, increment and
`sizeOf` operators, with bare `IDENTIFIER` at 5,145. No `LITERAL`,
`JUMP_TARGET` or `BLOCK` token survives into a label in that slice.

```bash
# at glaurung 935b7db1
python3 - <<'CENSUS'
import json, re, collections
from pathlib import Path
kinds = collections.Counter()
root = Path.home() / '.cache/glaurung/decbench-full/tree'
for p in sorted(root.glob('O0/*/source_cfgs/*.json'))[:120]:
    for fn in json.loads(p.read_text())['functions'].values():
        for lbl in fn['labels'].values():
            for line in lbl.split('\n')[1:]:
                if not line.startswith('<UnsupportedStmt: '):
                    continue
                body = line[18:]
                if body.startswith("['"):
                    kinds['<operator>.' + body[2:].split("'")[0]] += 1
                else:
                    m = re.match(r'([A-Z][A-Z_]+),', body)
                    if m:
                        kinds[m.group(1)] += 1
print(kinds.most_common(30))
CENSUS
```

zlib `putShortMSB` — two source lines — arrives as 25 CFG nodes before
coalescing, one each for `FIELD_IDENTIFIER pending_buf`,
`indirectFieldAccess s->pending_buf`, `postIncrement s->pending++`, `cast`,
`arithmeticShiftRight`, and so on. **After coalescing they are one block**,
which is the reason a reimplementation does not have to model Joern's
expression granularity to match its node counts — only its forks and joins
(§1.4, and REQ-CFG-1 in [`requirements.md`](requirements.md)).

Each DOT node's `label` holds one line per statement, shaped
`(<NODE_TYPE>,<code>,<enclosing code>)<SUB><line></SUB>`. That `<SUB>` line
number is the only positional information that survives.

### 1.3 Stages 5–6 — DOT to JIL

`pyjoern.cfg.parse_dot_cfg_string` runs the DOT through `pygraphviz` into an
`nx.DiGraph`. `pyjoern.cfg.jil.lifter.lift_graph` then makes **one `Block` per
DOT node**, parsing each label line into a JIL statement:

* `METHOD…` → `Nop(FUNC_START)`, `METHOD_RETURN…` → `Nop(FUNC_END)`;
* `<operator>.{assignment,plus,minus,logicalAnd,logicalOr,equals,greaterThan,…}`
  → `Assignment` / `BinOp` / `Compare`;
* `RETURN` → `Return`; a call shape → `Call`; `PARAM` → `Parameter`;
* everything else → `UnsupportedStmt`;
* a DOT node with **no label at all** → a block holding a single `Nop(NOP)`,
  addressed `0 - int(node_id)`.

The block's address is the `<SUB>` line of its first statement, disambiguated by
an occurrence index. Addresses play no part in GED.

**The JIL statement vocabulary is almost entirely unused.** Over the 800
published binaries, 69.2% of all statement lines are `UnsupportedStmt`
(`uv run python tools/source_cfg_census.py ~/.cache/glaurung/decbench-full/tree`,
at `935b7db1`). Only two statement facts are ever read downstream: whether a
statement is a `Nop`, and if so whether it is `FUNC_START` or `FUNC_END`.

### 1.4 Stage 7 — coalescing and the funcend rule

`pyjoern.cfg.normalize_cfg` applies two transforms, in this order.

**`cfgutils.transformations.to_supergraph`** repeatedly merges `src → dst`
whenever `src` has exactly one successor and `dst` exactly one predecessor. This
is ordinary maximal-linear-chain coalescing; the resulting partition is unique
regardless of visit order. `GenericBlock.merge_blocks` concatenates statement
lists and ORs the entry/exit flags, so a merged block is an entry block if any
constituent was.

`Block.is_entrypoint` / `is_exitpoint` are **derived**, not stored: a block is an
entry point if its first statement is `Nop(FUNC_START)` (or, for a merged block,
if any statement is), and an exit point if its last statement is
`Nop(FUNC_END)` (again, any statement for a merged block).

**Funcend removal** then deletes the `METHOD_RETURN` block — but *only when it is
a singleton*: `out_degree == 0`, exactly one statement, that statement a
`Nop(FUNC_END)`, and exactly one such block in the graph. Joern gives every
`return` an edge to one shared method-return node, which would otherwise
dominate node- and edge-count-sensitive metrics.

The consequence is a two-regime output that a reimplementation must reproduce
exactly:

* a function whose `METHOD_RETURN` stayed a singleton loses it, **and loses its
  in-edges with it**, so its `return` blocks end with out-degree 0 and the
  function has **no exit-flagged node at all**;
* a function linear enough that `METHOD_RETURN` was coalesced into a larger
  block keeps that block, flagged `is_exitpoint`.

Measured over the published corpus: **44,832 of 91,548 functions (49.0%) carry
no exit flag**, and 1,334 carry more than one entry flag. None carry zero entry
flags, and none carry more than one exit flag.

### 1.5 Stage 8 — which body scores which binary

`Function.from_many` drops functions whose name starts with `<`, `+`, `*`, `(`,
`>`, `JUMPOUT`, or `__builtin_unreachable`, drops empty CFGs, and for a repeated
`(name, filename)` keeps the CFG with more nodes — the mechanism that stops a
declaration-only view from displacing a real body.

Above that, `decbench/utils/cfg.py` resolves per translation unit:
`resolved_source_for_binary` prefers the CFG from the binary's **own** TU
(`nologin` binary ↔ `nologin.i`) and falls back to `best_source_by_name`
(cross-TU, non-degenerate, largest) only for names the own TU does not define.
A project-wide name-keyed union is explicitly not valid: it scored one binary's
5-node `main` against another binary's 56-node `main`.

`is_degenerate_source_cfg` marks a CFG unscorable when it has zero nodes, or one
node whose statements are all `Nop` — an empty prototype Joern emitted from a
declaration-only view. A genuine one-block function with real statements is
**not** degenerate and stays scorable. Degenerate CFGs return non-finite from
the metric and leave GED's denominator for every decompiler uniformly. Measured:
2,534 of 91,548 (2.77%).

## 2. What GED actually reads

`cfgutils.similarity.vj_ged` is not exact graph edit distance. It is the
Vujosevic–Janicic bipartite approximation: build an `(n+m) x (n+m)` cost matrix
and solve it with Munkres.

| matrix region | cost |
|---|---|
| top-left `n x m` (substitute node *i* for node *j*) | `\|c_i - c_j\| + \|p_i - p_j\|` plus `100000` on the first entry/exit mismatch |
| top-right diagonal (delete node *i* of g1) | `1 + p_i + c_i` |
| bottom-left diagonal (insert node *j* of g2) | `1 + p_j + c_j` |
| bottom-right (dummy assigned to dummy) | **`0`** |
| the rest of the two off-diagonal blocks | `inf` |

where `p` and `c` are in- and out-degree. The published cost expression is
`c_i + c_j - 2·common(CL_i, CL_j)` over lists of identical tokens, which is
`|c_i - c_j|`; the entry/exit penalty is an `if/elif` chain, so at most one
`100000` is ever added even when both flags disagree.

**Therefore GED is a function of the two degree sequences and the entry/exit
flags, and of nothing else.** Node labels, statements, block addresses and the
actual wiring are invisible to it. Two graphs with the same multiset of
`(in_degree, out_degree, is_entrypoint, is_exitpoint)` tuples always score 0
against each other:

```bash
# at glaurung 935b7db1; needs the DecBench venv for cfgutils
/nas4/data/workspace-infosec/decbench/.venv/bin/python - <<'PY'
import networkx as nx
from cfgutils.similarity import vj_ged
class N:
    def __init__(s,i,e=False,x=False): s.i=i; s.is_entrypoint=e; s.is_exitpoint=x
    def __hash__(s): return hash(s.i)
    def __eq__(s,o): return isinstance(o,N) and o.i==s.i
def g(edges,n,entry=0,exits=()):
    G=nx.DiGraph(); v={i:N(i,i==entry,i in exits) for i in range(n)}
    G.add_nodes_from(v.values()); [G.add_edge(v[a],v[b]) for a,b in edges]; return G
C = g([(0,1),(1,2),(2,3),(3,0)],4,0,(3,))   # one 4-cycle
D = g([(0,1),(1,0),(2,3),(3,2)],4,0,(3,))   # two 2-cycles
print(vj_ged(C,D))                          # -> 0
PY
```

This is the single most useful fact in this document. It sets the parity bar for
a reimplementation precisely — reproduce the degree sequence and the two flags —
and it means a structurally wrong CFG with the right degrees is, to DecBench,
indistinguishable from a right one. It also bounds the work: none of Joern's
type resolution, data flow, call graph or symbol handling reaches the score.

Two guards sit on top:

* `GED_MAX_NODES` (`decbench/metrics/ged.py`, default 60, `DECBENCH_GED_MAX_NODES`)
  — above it the metric returns `|Δnodes| + |Δedges|` and tags the result
  `approximated: True`. 2,820 of 91,548 functions (3.1%) are over the cap.
* The metric is cached content-addressably on both CFG structures with
  `cache_version = "2"`.

## 3. The measured shape of the output

`uv run python tools/source_cfg_census.py ~/.cache/glaurung/decbench-full/tree`,
run at `935b7db1` against dataset revision `e5eb576` (`full` config, 803
binaries), 2.1 s:

```
binaries       800
functions      91548
nodes / edges  1101674 / 1471410
mean nodes     12.03 (edges 16.07)
degenerate     2534
no entry flag  0     multi-entry 1334
no exit flag   44832 multi-exit  0
> 60 nodes     2820
functions by opt O0=33300, O2=24754, O2-noinline=33494
node buckets   1=26783, 2-3=11386, 4-7=18544, 8-15=17138, 16-31=10406, 32-60=4471, >60=2820
statement lines 5465854
  UnsupportedStmt   3781498  69.2%
  other              939351  17.2%
  Assignment         483223   8.8%
  Return             114781   2.1%
  Nop.FUNC_START     100285   1.8%
  Nop.FUNC_END        46716   0.9%
```

Two numbers shape the engineering: **29% of all functions coalesce to a single
node**, and the mean is 12. This is a small-graph problem. The tail past
`GED_MAX_NODES` is 3.1% and is scored by a formula that needs no graph algorithm
at all.

## 4. Construct by construct

The following shapes are read off published CFGs, not inferred. Each is quoted
with the binary it came from; reproduce any of them with

```bash
python3 -c "import json,sys;d=json.load(open(sys.argv[1]));f=d['functions'][sys.argv[2]];print(f['edges'],f['entry'],f['exit']);[print(k,repr(f['labels'][k])) for k in sorted(f['labels'],key=int)]" \
  ~/.cache/glaurung/decbench-full/tree/O0/<project>/source_cfgs/<binary>.json <function>
```

**`if` / `else`.** The condition is the last statement of its block and the
block has out-degree 2. zlib `flush_pending` (`O0/zlib/example`, 6 nodes,
6 edges, entry `[4]`, exit `[]`) is the canonical shape: block 4 ends
`len > strm->avail_out` and forks to 0 and 2; block 2 is the then-arm
(`len = strm->avail_out`) and joins at 0; block 0 ends `len == 0` and forks to
1 (`return ;`) and 5 (the `memcpy` body). Blocks 1 and 3 have out-degree 0
because the singleton `METHOD_RETURN` was removed.

**`&&` / `||`.** Short-circuit operators are real CFG forks, and the operator
node itself is a node. base-passwd `xmalloc` (`O0/base-passwd/update-passwd`,
6 nodes, 8 edges) holds `if (p == 0 && n == 0)` as: entry block 4 ends
`p == 0` and forks to block 1 (`n == 0`, the right operand) and block 0 (the
`&&` node, taken on short-circuit); block 1 also flows to block 0; block 0
forks to the two arms. So one `&&` costs three nodes and four edges, and its
operator node has in-degree 2 and out-degree 2.

**`switch`.** The switch selector is one node whose out-degree is the number of
distinct jump targets. bash `get_cmd_xmap_from_edit_mode`
(`O0/bash/bash`, 6 nodes, 6 edges) has an `IDENTIFIER,rl_editing_mode,switch(rl_editing_mode)`
node with out-degree 3 — two cases and the fall-out.

**Loops.** `for` and `while` appear as an `IDENTIFIER` node whose enclosing code
is the whole loop header (`for(walk=*head;walk;walk=walk->next)`), with the back
edge closing onto the condition node. Loop bodies contribute the usual
fork/join structure.

**`return` and the function end.** Every `return` is a node with an edge to the
shared `METHOD_RETURN` node, which is then removed if it stayed a singleton
(§1.4). A function with a single `return` at the end of a straight-line body
coalesces to exactly one block that is both entry and exit — zlib `adler32`
(1 node, 0 edges, entry `[0]`, exit `[0]`, non-degenerate).

## 5. What Joern loses, and who pays

The site's own dataset payload records the failure rates
(`$DECBENCH_DIR/site/data/dataset.json`, keys `joern.source` and `joern.output`):

| side | failed | scope | rate |
|---|---|---|---|
| source (`.i` → CFG) | 4,737 | 94,575 | 5.01% |
| kuna output | 0 | 83,298 | 0.00% |
| ghidra output | 33 | 73,791 | 0.04% |
| ida output | 504 | 83,417 | 0.60% |
| angr output | 1,906 | 84,661 | 2.25% |
| r2dec output | 2,462 | 62,631 | 3.93% |
| binja output | 7,003 | 63,729 | 10.99% |
| dewolf output | 21,715 | 35,019 | 62.01% |

The source-side 5.01% leaves GED's denominator for everyone, uniformly — that is
fair. The output-side rates do not: a function Joern cannot parse out of *your*
C is your not-perfect miss, in a denominator someone else's parse kept
measurable. **A decompiler is therefore scored partly on how palatable its
output is to Eclipse CDT**, which is why `sanitize_decompiled_c` exists and why
the control-byte escape (DecBench `d78d103`) mattered: it converted whole-file
losses into zero losses.

Three failure modes are worth naming because a reimplementation inherits the
obligation to be no worse:

1. **Whole-file voiding.** Non-JSON on stdout fails every function of the file.
2. **Silent header-bloat timeouts.** Before `strip_system_headers`, GED
   "source-parse failures" were really Joern timing out on megabytes of glibc.
3. **Silent total absence.** If `.i` files are missing, `pipeline/evaluate.py`
   takes its "No preprocessed sources" branch and GED is `None` for every
   function of the run, with no error. Do not disable `Project.emit_preprocessed`
   or `-save-temps=obj`.

## 6. Cost

One JVM boot, one Eclipse CDT parse, and one CPG build per file. In this repo's
terms that is the 56-cell `tools/decbench_matrix.py` gate at roughly 37 minutes
(`docs/development/decompiler-testing.md`), a JVM per cell, which is why the
DecBench lanes are opt-in and why `scripts/decbench-local-gate.sh` puts them
behind `--decbench`. The 1.9 GB `joern-cli` bundle is also a supply-chain
liability with a recorded failure: the pyjoern wheel can ship a mismatched
`joern-cli` (1.2.18 jars under a 4.x wrapper) which breaks `parse_source`
silently, so GED scores nothing at all.

Against that, the published dataset already contains 800 serialized source CFGs,
which is what makes the offline `--source-cfgs` flow — and the parity plan in
this directory — possible without running Joern once.
