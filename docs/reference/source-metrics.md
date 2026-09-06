# Source metrics for C

> **Kind:** reference · **Status:** maintained

Every metric `glaurung.source` computes, defined precisely enough to reproduce,
and the places where implementations disagree written out rather than implied.

Everything Glaurung measured about C before this existed was a **comparison** —
graph edit distance, tree edit distance, type match, byte match — four metrics
that score a decompilation against a ground truth and mean nothing with only one
side. Those cover benchmarking and nothing else. These are the other kind: a
property of a single piece of source.

* Rust: [`src/csource/metrics/`](../../src/csource/metrics/mod.rs), on the
  language-neutral half in [`src/syntax/metrics.rs`](../../src/syntax/metrics.rs)
* Python: `glaurung.source` (`python/glaurung/source.py`)
* CLI: `glaurung source-metrics`

## Quick start

```python
import glaurung

report = glaurung.source.analyze_path("prog.c")
for f in report.hotspots(by="cognitive", limit=10):
    print(f.name, f.cyclomatic, f.cognitive, f.max_nesting)
```

```console
$ uv run glaurung source-metrics tests/decbench_corpus/src --limit 6 --sort cyclomatic
14 file(s), 61 lines, 30 function(s); top 6 by cyclomatic
function                            cyc  cog nest loops lines calls  location
fsm                                  10   16    4     1     6     0  tests/decbench_corpus/src/statemachine.c:1
dispatch                              9    1    1     0     4     0  tests/decbench_corpus/src/switch_jt.c:1
bsearch_i                             4    6    2     1     2     0  tests/decbench_corpus/src/sort.c:3
bubble                                4    6    3     2     2     0  tests/decbench_corpus/src/sort.c:1
matmul                                4    6    3     3     3     0  tests/decbench_corpus/src/matrix.c:1
str_cmp                               4    2    1     1     1     0  tests/decbench_corpus/src/strops.c:2
```

Run at `e78d8080` plus the uncommitted change this page documents. Read the top two rows together: `dispatch` is a nine-arm
`switch` — nine decisions, but one flat construct a reader takes in at a glance,
so cyclomatic 9 and cognitive 1. `fsm` is a `switch` inside a loop with nested
`if`s — cyclomatic 10, cognitive 16. That gap is the reason both are reported.

## Totality

`analyze` never raises on account of its input. A file that is not C yields zero
functions and the diagnostics saying so; a file whose third function is
unparseable still reports the other two. A caller cannot otherwise distinguish
"this file defines nothing" from "this file failed", and both are ordinary
outcomes when the input is a decompiler's output.

## The metrics

### Size

| name | definition |
|---|---|
| `lines` | `last_line - first_line + 1` over the definition's span |
| `code_lines` | lines on which **at least one token begins** |
| `tokens` | tokens in the definition |
| `bytes` | bytes in the definition |
| `parameters` | declared parameters; `()` and `(void)` are both `0`, a trailing `...` is not counted |

At the file level the same rule partitions every line into exactly one of
`code_lines`, `blank_lines` (no non-whitespace byte) and `other_lines`.

**`other_lines` is not called `comment_lines`, deliberately.** The lexer stores
no trivia — whitespace and comments never become tokens — so the token buffer
cannot tell a comment from the second line of a multi-line string literal.
Defining a code line as "a line a token begins on" means the count is computed
from what the parser actually consumed and cannot drift from it; naming the
complement for its majority case would be a claim the data does not support.

### Control flow

Computed on the **general** CFG — the graph a person would draw, with real
successors, real join points and real loop back edges. Never on the
Joern-parity CFG, which reproduces another tool's artifacts so one similarity
score can be compared against it; see
[static-c-analysis/architecture.md](../design/static-c-analysis/architecture.md)
§1.

| name | definition |
|---|---|
| `cyclomatic` | `E - N + 2` over the subgraph **reachable from the entry**, floored at 1 |
| `decision_points` | `sum(max(0, out_degree - 1))` over reachable nodes |
| `loops` | distinct back-edge destinations — one per natural loop |
| `back_edges` | edges the builder marked as returning to an enclosing loop head |
| `dead_end_nodes` | reachable nodes from which the function end cannot be reached |
| `node_kinds` | how many CFG nodes carry each kind: `entry`, `exit`, `stmt`, `cond`, `loop_header`, `switch`, `case`, `label`, `goto`, `break`, `continue`, `return`, `diverge` |
| `gotos` | `goto` transfers, i.e. `node_kinds["goto"]`, surfaced because it is the headline number for judging decompiler output |
| `is_structured` | whether the function contains no `goto`. A statement about the *text*, not about what is possible: a function that could have been written without one but was not reads `False` |
| `edge_kinds` | the same census for `fall`, `true`, `false`, `case`, `default`, `fall_through`, `jump` |

**Why `cyclomatic` and `decision_points` are both reported.** The textbook
identity `E - N + 2 == decisions + 1` holds for a graph with a single sink. A
construct with no successor — an unresolved transfer, a `noreturn` call — adds a
sink, and then `E - N + 2` is lower. Handing over one of the two silently would
hide that; `cyclomatic <= decision_points + 1` is asserted over the whole
fixture corpus.

Restricting to the reachable subgraph is what makes McCabe's `P = 1` true. A
partly recovered function leaves nodes no path reaches, and counting them would
report a disconnected graph's number under a formula that assumes one component.

### `unreachable_statements`

Statements the source contains that no path from the entry reaches: code after a
`return`, code after a `goto`, an arm no `case` selects.

This is **not** `graph.unreachable_nodes`, which is structurally zero. The
general CFG contains only reachable statements by construction — an unreachable
one is never emitted — so the figure comes from a second, syntax-directed build
in which an unreachable region becomes a component with no path from the entry.

**It is a lower bound.** The front end does not fold constants, so the statement
after `for (;;) { }` is not counted: the loop header still carries a false arm
to it. What is counted is genuinely unreachable; what is not counted may still
be. `unreachable_detection_is_a_lower_bound_after_an_always_true_loop` pins
this, so the day it improves the test says so.

### Shape

| name | definition |
|---|---|
| `max_nesting` | deepest nesting of control structures, in levels |
| `max_loop_depth` | deepest nesting of loops specifically |
| `cognitive` | cognitive complexity — see below |
| `calls` | call expressions, one per argument list, so `f(g(x))` is 2 |
| `callees` | distinct **directly named** callees, sorted |
| `statements` | statement nodes of any kind |
| `tag_counts` | how many AST nodes carry each C node tag (`if_stmt`, `goto_stmt`, …) |
| `short_circuits` | `&&`, `||` and `?:` operators the graph builder expanded into forks |

A call through a function pointer or a struct member counts toward `calls` and
appears in `callees` under no name, because there is none.

### Cognitive complexity

G. Ann Campbell's *Cognitive Complexity* specification (SonarSource,
2016–2021), restricted to the C constructs that exist here. An unstated variant
of this metric is not comparable with anyone else's, so:

* **+1 plus the current nesting level** for `if`, `switch`, `while`, `do`,
  `for`, and the `?:` conditional operator;
* **+1 with no nesting penalty** for `else`, for an `else if`, and for `goto`;
* **+1 per run of like binary logical operators** — `a && b && c` is one run and
  scores 1, `a && b || c` is two runs and scores 2;
* **nesting increases** on entering the body of any structure in the first
  bullet and nowhere else. A plain compound statement does not nest; a `case`
  arm does not nest inside its `switch`.

Not charging an `else if` the nesting its textual position implies is the single
largest divergence between implementations of this metric. An
`if`/`else if`/`else` ladder reads as one decision, so it is charged as one
increment per arm and no nesting.

Recursion is **not** charged (the specification's +1 for a recursive call): it
needs a call graph, and one function's text is not enough to know that a name
resolves back to the enclosing function rather than to a different declaration
with the same spelling.

### Halstead

The operator/operand split, written down because implementations differ and the
resulting numbers are not comparable across them:

* **Operands** are identifiers and the four literal kinds. Distinct by
  **lexeme**, so `i` used twice is one distinct operand and `1` and `1u` are
  two.
* **Operators** are keywords and punctuators. Distinct by **kind**, so `+`
  everywhere is one distinct operator, and the keyword aliases the lexer folds
  together (`__const` and `const`) are one operator because they are one kind.
* **The closing half of a matched pair does not count.** `)`, `]` and `}` are
  skipped, so `f(x)` costs one operator for the call parentheses, not two.
* **Lexer artifacts do not count at all.** An unclassifiable byte and a
  decompiler's inline register note are not program text.

Reported: `distinct_operators` (n1), `distinct_operands` (n2),
`total_operators` (N1), `total_operands` (N2), `vocabulary` (n), `length` (N),
`volume` (`N·log2 n`), `difficulty` (`(n1/2)·(N2/n2)`), `effort` (`D·V`). All
four counts are reported, so a caller who wants a different convention's derived
figure can compute it.

Measured on `tests/decbench_corpus/src/statemachine.c`, same tree:

```python
>>> f = glaurung.source.analyze_path("tests/decbench_corpus/src/statemachine.c").functions[0]
>>> f.name, f.cyclomatic, f.cognitive, f.max_nesting
('fsm', 10, 16, 4)
>>> dict(f.node_kinds)
{'entry': 1, 'exit': 1, 'stmt': 19, 'cond': 4, 'loop_header': 1, 'switch': 1,
 'case': 4, 'break': 3, 'return': 2}
```

## The Python API

| call | returns |
|---|---|
| `analyze(code, *, name=None, dialect=None)` | a `SourceReport` |
| `analyze_path(path, *, dialect=None)` | the same, reading the file lossily |
| `functions(code)` | name and span per definition, **without** building graphs |
| `control_flow_graphs(code)` | the general CFG per function: typed nodes and edges |
| `feature_names()` | the fixed column vector, in order |
| `features(code)` | `(name, row)` per function, each row as long as `feature_names()` |
| `normalize(code, dialect)` | the normalized text |
| `compare(before, after, *, metrics=...)` | per-function movement between two reports |

`SourceReport` carries `.functions`, `.diagnostics`, `.lines`, `.code_lines`,
`.blank_lines`, `.other_lines`, `.source` and `.to_dict()`, plus four methods:

| method | returns |
|---|---|
| `.hotspots(by="cognitive", limit=10)` | the functions scoring highest on one metric, descending, name as tie-break. Raises `ValueError` on an unknown metric rather than quietly returning source order |
| `.summary()` | whole-unit aggregates: line counts, function count, `structured_functions`, total `gotos` and `unreachable_statements`, and `min`/`median`/`mean`/`max` per metric |
| `.call_graph()` | `{caller: (callee, ...)}` over measured functions |
| `.defined_names()` | the function names this unit defines |

Two deliberate choices in those last three. **`summary()` on a unit with no
functions returns the same keys with `distributions` empty rather than zeroed** —
a mean of zero over no functions reads like a measurement and is not one.
**`call_graph()` keeps edges to names this unit does not define** (a call to
`malloc` is a real edge, and dropping it would make the function look like it
calls nothing) and **contributes no edge for an indirect call**, because there is
no name to record; intersect with `defined_names()` for the internal-only graph.
`calls` and the call-graph edge count therefore disagree exactly where a pointer
or a struct member was called, which is the useful signal rather than a
discrepancy.

`features` exists for the **stable column vector**, not for speed. Measured over
`tests/decompiler_fixtures/src` (196 files, 900 functions, 0.78 MB) on a
`maturin develop --release` build, best of five: `analyze` 43.8 ms, `features`
41.3 ms — 0.94x. Parsing and graph construction dominate; the nested dicts are
6% of the run, not most of it. What a row buys is a meaning fixed by
`feature_names()` that does not move when the report's dict schema gains a key.

### Comparing two measurements

Build-over-build regression tracking and cross-decompiler comparison are the
same operation: measure two pieces of C, match their functions by name, and read
what moved.

```python
before = glaurung.source.analyze_path("tests/decompiler_fixtures/src/03_loop_shapes.c")
after  = glaurung.source.analyze_path("03_dec.c", dialect="decompiled")
result = glaurung.source.compare(before, after)
```

Source against our own decompiler's output, same tree:

```text
matched 19  added 8  removed 0
totals   cognitive  37 -> 49  (+12)
         gotos       0 ->  6   (+6)

cond_reload_and_transform  cyclomatic-1 cognitive+1 max_nesting+1 lines+11 statements+7
loop_break                 cognitive+1 max_nesting-1 gotos+2 lines+9 statements+10
cond_side_effect           cyclomatic+1 cognitive+2 max_nesting+1 lines+8 statements+6
dowhile_atleastonce        cyclomatic+1 cognitive+3 max_nesting+1 lines+8 statements+7
```

`matched` is sorted by largest absolute delta, so what moved most reads first.
`totals` covers **matched functions only** — a total that mixed in added and
removed functions would attribute their whole weight to a regression.

Functions are matched by name; check `added`/`removed` when the counts do not
line up.

### Dialects, and one footgun

`normalize` rewrites the text, so every offset a report carries refers to the
normalized string. That is why it is a separate step and why
`SourceReport.source` holds the text the offsets describe.

`dialect="preprocessed"` strips everything not under a line marker naming a
non-system file, and the stripper **starts in the "inside a system header"
state**. Ordinary C, which has no line markers at all, is therefore stripped to
nothing: passing `"preprocessed"` for a plain `.c` file yields zero functions and
no diagnostic. Use it only for a real gcc `.i` unit. Pinned by
`test_the_preprocessed_dialect_strips_everything_without_a_line_marker`.

## The CLI

```console
$ glaurung source-metrics PATH... [--sort METRIC] [--limit N]
                                  [--dialect preprocessed|decompiled]
                                  [--summary] [--json | --csv]
                                  [--fail-over METRIC=N ...]
```

Directories are searched recursively for `*.c` and `*.h`. Four output shapes,
because the use cases want different things:

| flag | shape |
|---|---|
| *(default)* | one ranked function table across every file measured |
| `--summary` | one aggregate line per file, plus a `TOTAL` |
| `--json` | the full report per file; with `--summary`, the aggregates |
| `--csv` | the feature matrix, `path,function,…` header, one row per function |

`--summary` is the whole-tree view — which files carry the complexity, and where
the unstructured control flow is:

```console
$ glaurung source-metrics tests/decbench_corpus/src --summary
file                                                  fns  lines maxcyc maxcog  goto  dead
tests/decbench_corpus/src/arith.c                       3      4      3      2     0     0
tests/decbench_corpus/src/arrays.c                      3      4      3      3     0     0
tests/decbench_corpus/src/branches.c                    2      3      3      4     0     0
...
TOTAL                                                  30     61                   0     0
```

`--fail-over` is repeatable, lists every violation on stderr, and **exits 1** —
a malformed or unknown metric exits 2 rather than leaving the gate silently
passing:

```console
$ glaurung source-metrics src/ --fail-over cyclomatic=25 --fail-over max_nesting=5
```

## Exporting the graphs

The same parse also serializes, which is what replaces `joern-export` for the
two representations this front end has.

```console
$ glaurung source-graph PATH... [--repr cfg|ast]
                                [--graph-format dot|graphml|json|mermaid]
                                [--func NAME] [-o DIR] [--dialect ...]
```

```python
for name, body in glaurung.source.export_graphs(code, repr="cfg", format="json"):
    graph = networkx.node_link_graph(json.loads(body))
```

`--repr` takes Joern's spelling of the two graphs we have. Joern also offers
`cdg`, `ddg` and `pdg`; each needs a data-dependence analysis this front end
does not do, and each **raises** rather than returning a control-flow graph
under another name.

**`repr="cfg"` is the general graph, never the Joern-parity one** --- the same
rule the metrics follow, for the reason
[static-c-analysis/architecture.md](../design/static-c-analysis/architecture.md)
section 1 gives. `glaurung.source_cfg.parity_cfgs` is still there when the
parity shape is what you want.

| format | what it is for |
|---|---|
| `dot` | Graphviz. Human-readable, and what `glaurung graph` already emits for binary CFGs |
| `graphml` | The interchange standard: `networkx`, `igraph`, `JGraphT`, Gephi and yEd all read it, and so does anything built on `joern-export --format graphml` |
| `json` | Node-link JSON. The edge array is under **`edges`**, which is what `networkx.node_link_graph` reads by default since NetworkX 3.6 removed the `link` keyword deprecated in 3.4 |
| `mermaid` | Renders in Markdown, on GitHub, and in a chat transcript with no Graphviz install |

GraphSON and Neo4j CSV are deliberately absent: both exist in `joern-export` to
feed a graph database, which is the code-property-graph path
[requirements.md](../design/static-c-analysis/requirements.md) section 8
declines.

Node labels carry the node kind and the source the node covers, because a graph
whose nodes all read `stmt` tells a reader nothing; every node also carries its
`span`, so an exported graph is traceable back to the text. A CFG edge carries
its kind and whether it is a back edge. Mermaid has no attribute channel, so
only labels survive there.

The CLI writes to stdout by default, one graph after another with a comment
naming each where the format has comments. `-o DIR` writes one file per
function instead, the way `joern-export` does; the file stem carries the
function's index as well as its name, because two definitions in one file can
carry the same name after recovery.

**`--graph-format`, not `--format`.** Every Glaurung command already has
`--format` for its own output shape (`plain`, `rich`, `json`, `jsonl`), and
`json` is a legal value of both. Merging them would make `--format json`
silently change the graph encoding.

## Data dependence

Which write each read can see. A reaching-definitions fixpoint over the general
CFG, exposed three ways:

```console
$ glaurung source-graph PATH --repr ddg [--graph-format ...]
```

```python
for flow in glaurung.source.data_flow(code):
    dead = [flow["definitions"][i]["name"] for i in flow["dead_stores"]]
```

`--repr` now covers every representation `joern-export` offers except `cpg14`,
which is a code property graph and the one thing
[requirements.md](../design/static-c-analysis/requirements.md) section 8
declines: `cfg`, `ast`, `ddg`, `cdg` and `pdg`.

### Measured against Joern

Both front ends on one 17-line file, in one CPython 3.12 process, 2026-09-05:

| | nodes | edges | edges naming a variable |
|---|---:|---:|---:|
| Joern / Eclipse CDT | 13 | 23 | **0** |
| Glaurung | 11 | 8 | **8** |

pyjoern's `Function.ddg` returns every edge with an empty attribute dict, so a
consumer cannot tell which value an edge is about. Ours names the variable on
the edge and on both endpoints, with the kind of write and the byte range.

The edge counts differ because the graphs are different things. Joern's is over
CFG blocks: 9 of its 23 edges leave `FUNCTION_START` and 5 enter
`FUNCTION_END`, which record reachability rather than a value flowing. Audited
edge by edge, all 8 of ours are real definition-to-use pairs, and none of
Joern's 23 is one we lost.

### What it models, and what it does not

| | |
|---|---|
| **Scoping** | A shadowed `int x` in a nested block is a different variable. Resolution is innermost-visible-binding at the point of use |
| **Definitions** | Parameters, initialized declarators, `=`, compound assignment, `++`/`--`, and `&x` |
| **`int x;`** | Declares, does **not** define. A read of it is an unresolved use, which is the read-of-uninitialized it is. `int a[8];` does define `a` — the address is well-defined |
| **`a[i] = v`, `s.f = v`, `*p = v`** | A **use** of the base, never a definition of it. Calling them definitions would kill the base's real reaching definition, which loses edges rather than adding them |
| **`&x`** | Recorded as a definition. Taking an address is how C spells an out parameter, and the callee may write through it |
| **Aliasing** | None. A store through a pointer kills nothing, so the graph over-approximates: an edge may be spurious, no real dependence is missing |
| **Interprocedural** | None. A call reads its arguments and defines nothing |

### The two defect counts

**Dead stores** — a write no read can see. **Unresolved uses** — a read no
write reaches: a global, a macro constant, a name from a header this parser
never saw, or a genuine read of uninitialized storage.

A write to a global is never counted dead: it escapes the function, and the
read that observes it is somewhere this analysis cannot see. An unread
parameter is not counted either — the caller wrote it and the signature is the
contract.

### What the dead-store count is for

Measured over ten fixtures and our own decompiler's output for the same ten,
at engine commit `a4207caf`:

| | functions | writes | dead stores |
|---|---:|---:|---:|
| hand-written source | 84 | 380 | **0** (0.0%) |
| our decompiler's output | 174 | 729 | **33** (4.5%) |

Every one of those 33 is a write the recovered code performs and never reads.
The execution differential passes all of them — the return value is still
right — so this is a readability defect that no test in the existing estate
reports. It is the source-side companion to `defuse_baseline.json`, which asks
the same question of the binary.

The corpus-wide figure for hand-written C is 12 dead stores over 900 functions,
and a Rust test fails if that ratio moves by more than an order of magnitude.
Each round of over-reporting during development tripped exactly that assertion:
897 when a bare `int x;` counted as a store, 460 when a write to a global
counted, 27 when `++a[i]` counted as a write to `a`.

## Declared types

Every binding carries the type **as the source spells it**.

```python
for flow in glaurung.source.data_flow(code):
    for binding in flow["bindings"]:
        print(binding["name"], binding["type"], binding["pointer_depth"])
```

| field | meaning |
|---|---|
| `type` | the rendered type: `const char *`, `struct point *`, `int` |
| `specifiers` | the declaration specifiers, whitespace-collapsed |
| `pointer_depth` | `char **argv` is 2 |
| `array_rank` | `int m[4][4]` is 2 |
| `is_const`, `is_volatile` | qualifier flags. A dead store to a `volatile` is not dead |

Each definition and use carries a `binding` index, so the three lists join. A
definition also carries `declared_type` — the type written at *that* site,
`None` for an assignment, which declares nothing.

**Types are not resolved.** This reads one translation unit and does not
process `#include`, so a typedef from a header is an opaque name: `uint32_t` is
recorded as `uint32_t`, and nothing claims to know it is four bytes. Two
spellings we cannot resolve compare as different, which is the honest answer
rather than a guess.

This deliberately does not use
[`metrics::type_name::normalize_type`](../../src/metrics/type_name.rs). That
function reproduces four defects in DecBench's reference implementation on
purpose — it emits the non-C spelling `long long long`, and turns `_Bool` into
`_bool` — because parity with the benchmark is its contract. A consumer who
wants the type the programmer wrote needs a different reader, so this is one.

### Two counts that come with it

**`type_conflicts`** lists bindings whose declaration sites disagree about
type. That cannot happen in code a C compiler accepted, and it is the shape of
a decompiler's type-recovery failure.

**`unused_bindings`** lists variables declared and never read. Distinct from a
dead store: `int *b;` is not a store at all, so it appears in neither the
definition list nor `dead_stores`, and without the binding table there is no
way to ask about it.

### Measured

Over `tests/decompiler_fixtures/src` (900 functions), and our own decompiler's
output for ten of them, at engine commit `5527d218`:

| | bindings | typed | conflicts | unused |
|---|---:|---:|---:|---:|
| hand-written source | 3,602 | **100%** | 0 | **0** |
| ten fixtures, source | 274 | 100% | 0 | **0** |
| the same ten, decompiled | 660 | 100% | 0 | **22** |

The source baselines are what make the decompiled number readable: hand-written
C types everything it binds and declares nothing it does not use, so 22 unused
declarations in recovered output is a real finding rather than a parser
artifact. It is the third defect class of this kind, beside dead stores and
control depth, and like both of those the execution differential passes every
one of them.

The most common specifiers in that decompiled output are `int` (229), `long`
(221) and `extern unsigned char` (80) — the last being how the recovered code
spells a reference to a data symbol it did not define.

## Across calls

The intraprocedural analysis stops at the call: a call reads its arguments and
defines nothing. Summaries cross it.

```python
for summary in glaurung.source.call_summaries(code):
    print(summary["name"], summary["parameters"], summary["complete"], summary["flows"])

glaurung.source.reaches(code, "parse_header", 0, "checksum")   # "yes" | "no" | "unknown"
```

For each function, which parameter reaches the return and which reaches which
other parameter, computed once and applied by callers rather than re-analysed.
**Summaries, not inlining** — inlining does not terminate on recursion, and a
summary is a set of `(parameter, sink)` pairs over a finite lattice, so
iterating to a fixed point converges. `f` calling `g` calling `f` costs one
extra round.

### Three answers, not two

`reaches` returns `"yes"`, `"no"` or **`"unknown"`**, and the third is not a
failure. It means the search met one of:

* **an indirect call** — `p(x)` names no callee, so no summary can be applied;
* **a callee this unit does not define** — `memcpy(dst, src, n)` is an edge to
  a name whose body is elsewhere, and what it does with its arguments is not
  knowable from one translation unit;
* **a bound** — the fixed point is capped so a pathological call graph costs an
  `unknown` and not a hang.

Reporting any of those as `"no"` would be a claim rather than an analysis. A
caller that treats `"unknown"` as `"no"` gets an unsound answer, which is why
it is a separate value rather than a flag.

`complete` on a summary carries the same information per function: `False` when
the body held something unresolvable, so a caller applying it inherits
`"unknown"`.

### The test that matters

```c
int strip(int x) { return 0; }
int carry(int y) { return y; }
int outer(int n) { return carry(n); }
```

`carry` propagates parameter 0 to its return; `strip` does not; and `outer`
propagates **only because `carry` does**. An analysis with no call-site rule
answers the same for both callees, which is right by accident and wrong in
general — the second case is what pins it.

### Measured

Over `tests/decompiler_fixtures/src`, 900 functions:

| | |
|---|---|
| functions summarized | 900 |
| parameter flows found | 1,731 |
| summaries marked incomplete | 254 |

The 254 are honest: those bodies contain an indirect call or a call to
something defined elsewhere, and the summary says so rather than guessing.

The incompleteness rate is itself a measurement, and it separates source from
recovered code. Ten fixtures and our own decompiler's output for the same ten:

| | functions | flows | incomplete |
|---|---:|---:|---:|
| source | 84 | 182 | 4 (**5%**) |
| decompiled | 169 | 194 | 50 (**30%**) |

Six times the rate. Recovered code turns direct calls into indirect ones and
splits functions the source did not have, so an interprocedural analysis can
see through less of it — which is worth knowing before trusting a `"no"` from
one, and is exactly what the third answer exists to say.

### What it does not do

No libc effect table. `memcpy` is an edge to a name, and a curated table of
what the standard library does with its arguments is the obvious next increment
— deliberately its own decision rather than smuggled in here.

## Control dependence and slicing

`--repr cdg` answers which branch decides each statement;
`--repr pdg` is that plus data dependence on one node set, which is the graph a
slice is taken from.

```python
for flow in glaurung.source.control_dependence(code):
    for node in flow["nodes"]:
        print(node["id"], node["kind"], node["depth"], node["ipdom"])

sliced = glaurung.source.backward_slice(code, "parse_header", 12)
```

Ferrante-Ottenstein-Warren control dependence, over a post-dominator tree built
with a **virtual exit** so a region that cannot reach the function end still has
one. Without that, a function whose body is `L: goto L;` has no post-dominator
tree at all and its control-dependence graph would come back empty rather than
wrong — a silent hole exactly where the interesting control flow is. Nodes that
reached the exit only through the synthetic edge are listed in
`unreachable_exit` rather than hidden.

**Every CDG edge names the arm that decides it** — `true`, `false`, `case`,
`default`. `joern-export --repr cdg` writes its edges with no label at all, so
"runs when the guard holds" and "runs when it does not" are indistinguishable
there.

Each node also carries `depth`: the longest chain of decisions above it. That is
a nesting measure computed on the graph, so unlike counting braces it is not
fooled by a `goto` that leaves a block or by a decompiler's flattened dispatch.

### Checked against Joern

`joern-export --repr cdg` on the same fixtures, compared on the pairs of source
lines each control dependence connects — Joern's nodes are expression-granular
and ours are CFG nodes, so the line pair is what the two can be judged on
identically:

| fixture | Joern's pairs | ours | agreed |
|---|---:|---:|---:|
| `03_loop_shapes.c` | 60 | 63 | **60** |
| `01_conditional_polarity.c` | 36 | 37 | **36** |
| `13_loop_early_exit.c` | 30 | 32 | **30** |
| `152_deep_nesting.c` | 176 | 177 | 174 |

We find every control dependence Joern finds on the first three. The two misses
on the fourth are one statement split across two lines, which Joern attributes
to the continuation and we attribute to the start — a granularity artifact of
the line comparison, not a missing edge.

`python/tests/test_source_dependence_joern.py` runs this. It is `decbench`-marked
and deselected by default, because it needs a JVM per file.

### What control depth is for

The same measurement against our own decompiler's output, matched by function
name over ten fixtures at engine commit `b1a03020`:

| | value |
|---|---|
| matched functions | 84 |
| deeper after decompilation | **26** |
| same | 55 |
| shallower | 3 |
| median depth, source → decompiled | **1 → 2** |

The worst cases are `trie_insert` 7 → 13 and `switch_in_loop` 2 → 7. The median
is quoted rather than the mean because a handful of functions carry it.

Nesting depth is a readability defect the execution differential cannot see:
the recovered code returns the right value at depth 13 exactly as it does at
depth 7. It is the control-flow companion to the dead-store count above.

### Slicing

`backward_slice` walks control and data dependence backwards to a fixed point,
returning every node whose execution or value can affect the seed. This is the
question a program-dependence graph exists to answer, and it needs both
relations over one node set — following only one silently omits the other's
reasons.

## Worked example: measuring our own decompiler

The loop this exists to close. Decompile a fixture object, measure the C that
comes out, and read the structural cost against the source it was built from:

```console
$ uv run glaurung decompile tests/decompiler_fixtures/build/03_loop_shapes-gcc-O0.so \
      --all --limit 40 --style decbench > /tmp/03_dec.c
```

```python
src = glaurung.source.analyze_path("tests/decompiler_fixtures/src/03_loop_shapes.c")
dec = glaurung.source.analyze_path("/tmp/03_dec.c", dialect="decompiled")
```

Same tree:

|  | source | decompiled |
|---|---:|---:|
| functions | 19 | 27 |
| `goto`s | 0 | 6 |
| structured functions | 19 | 24 |
| dead statements | 0 | 0 |
| parse diagnostics | 0 | 0 |

| function | cyc src | cyc dec | cog src | cog dec |
|---|---:|---:|---:|---:|
| `for_sum` | 2 | 2 | 1 | 1 |
| `while_prefix` | 4 | 3 | 2 | 3 |
| `while_reload_header` | 5 | 4 | 3 | 4 |
| `dowhile_atleastonce` | 3 | 4 | 2 | 5 |

All 19 source functions matched by name, and the decompiler's own C parsed with
zero diagnostics. The six `goto`s are the structurer giving up on six regions;
`dowhile_atleastonce` going from cognitive 2 to 5 is the same story per
function. Those are the numbers a structurer change should move, and nothing in
the existing gate estate reported them before.

`test_our_own_decompiler_output_measures_cleanly` runs this pipeline in CI
without pinning the numbers, which move with every structurer change.

## Performance

`maturin develop --release`, 196 files / 21,249 lines / 0.78 MB / 900 functions
of `tests/decompiler_fixtures/src`, best of five in-process runs, on the same
tree:

| entry point | wall | throughput |
|---|---|---|
| `analyze` | 43.8 ms | 17.7 MB/s, 20,549 functions/s |
| `features` | 41.3 ms | 18.8 MB/s |
| `functions` (parse only) | 10.6 ms | 73.6 MB/s |

A `maturin develop` build is DEBUG and roughly an order of magnitude slower;
these are the release figures.

## Path feasibility

Everything above reads the program's *structure*. This asks whether a path
through it can be taken by any input at all, by putting the branch conditions
to an SMT solver.

There are two entry points, and the split is the same one `analyze` and
`data_flow` already make: one answers about a **file** and reports only what is
worth reading, the other answers about a **function** and reports everything.

```python
# High level: every function in the unit that has something to say.
for found in glaurung.source.source_findings(code):
    print(found["function"], found["infeasible"], found["unreachable_blocks"],
          found["redundant_guards"], found["undefined_behavior"])

# Low level: one function, everything about it, bounds under your control.
report = glaurung.source.path_feasibility(code, "decide", max_block_visits=32)
for path in report["paths"]:
    print(path["decisions"], path["verdict"], path["args"], path["why"])
```

`source_findings` omits a function whose every path is feasible, whose guards
are all load bearing and which cannot be made to misbehave — the ordinary case,
which would otherwise bury the ones that are not. It also skips functions the
lowering refuses: "I could not read this" is not a finding about the program.
Ask `path_feasibility` by name to see the refusal.

Both return the same shape:

| key | |
|---|---|
| `function` | the name |
| `paths` | one entry per enumerated path: `decisions`, `verdict`, `args`, `why` |
| `feasible` / `infeasible` / `unknown` | counts over those paths |
| `unreachable_blocks` | addresses no input reaches |
| `cuts` / `total` | why paths were abandoned, and whether the enumeration covered the function |
| `abstained` | set when nothing could be decided, naming the reason |
| `redundant_guards` | decisions earlier decisions already force |
| `undefined_behavior` | inputs that make it misbehave, with the property |

The function is walked **once** for all four questions; asking them separately
would enumerate its paths three more times.

### Bounds

Four knobs, as keyword arguments on both calls: `max_paths`,
`max_block_visits`, `max_steps` and `solver_timeout_ms`. The rest of the
`Bounds` struct keeps defaults sized so a corpus sweep is minutes rather than
hours.

**`max_block_visits` is the one to raise first.** It is the loop unroll depth,
and it is why 510 of 1,131 corpus paths are cut rather than decided. Raising it
trades that for query size.

**This needs an extension built with the `symbolic` feature.** The default
wheel bundles the concrete emulator but not the symbolic engine or a solver, so
the function is always present and raises `RuntimeError` on a build that cannot
answer:

```bash
uv run maturin develop -F pyo3/extension-module,python-ext,symbolic
```

It raises rather than returning an empty list because "no paths" and "this
build cannot answer" are different facts, and a caller that cannot tell them
apart would record "nothing infeasible" for a function it never examined.

### Why an unchecked reachability answer is wrong

A path a graph reports as reachable may be takeable by no input. Measured over
`tests/decompiler_fixtures/src` (`cargo test --features symbolic --lib
csource::feasibility -- --nocapture`):

| | |
|---|---:|
| functions decided | 293 |
| paths decided | 1,131 |
| **infeasible** | **373 (33%)** |
| feasible | 746 |
| unknown | 12 |
| paths cut by a bound, no verdict | 510 |

A third of the paths cannot be taken. The shape that produces them is the
mutually-exclusive dispatch chain decompiler output is made of:

```c
if (first == (uint8_t)'H' && second == 0) return 101;
if (first == (uint8_t)'C' && second == 0) return 1201;
```

Each `&&` contributes two decisions, so a path can assume `first == 'H'` held,
`second == 0` did not, and then that `first == 'C'` holds — of one byte, at one
program point, with no assignment between. No graph can see that; it is a fact
about *values*.

### What it will not answer

The lowering accepts a subset of C and refuses the rest **by name**, and a
function it refuses returns one entry whose `why` carries the construct rather
than a verdict:

```python
>>> glaurung.source.path_feasibility("double f(double x) { return x; }", "f")
[{'decisions': None, 'verdict': 'unknown', 'args': None,
  'why': 'not lowered: unsupported at byte 0: floating-point type '
         '(no FP in the exec Domain) as a result'}]
```

A tool that reports "infeasible" when it means "I could not lower this" is
worse than one that reports nothing. Of 900 corpus functions, 403 do not lower
and a further 204 lower but have a non-integer parameter, for which there is no
input space to quantify over.

### Every witness is re-run, twice

A satisfying assignment is not taken on trust. The solver and our interpreter
do not agree everywhere — `Div` by zero is `0` concretely and all-ones under
SMT-LIB's `bvudiv`, and a shift at or above the operand width reduces modulo
the width concretely but saturates under `bvshl` — so agreement between them is
two readings of *our* semantics.

1. The interpreter re-runs the model as constants and must reach a path; one
   that does not becomes `unknown`, never a verdict.
2. Every solver-chosen input is fed to the binary **`gcc` built from the same
   source**: 745 witnesses, 600 decided, **0 diverged**. This is a sharper
   probe than a fixed vector set, because the solver does not pick round
   numbers — it picks whatever satisfies a guard, which is disproportionately a
   boundary.

### Three things built on it

All three arrive in the same result, under `unreachable_blocks`,
`redundant_guards` and `undefined_behavior`.

**Unreachable code.** A block that only infeasible paths reach is code no input
executes — 7 functions and 8 blocks in the corpus. Nothing is claimed unless
the path enumeration was *total*: with even one path cut by a bound, "every
path I looked at is infeasible" is not "no input gets here".

**Redundant guards.** A decision earlier decisions already force. `x > 10`
forces `x > 0`, so this is a solver query and not a syntactic one. Only
satisfiable paths are examined, because implication is vacuous from a
contradiction and a naive version turns one infeasible path into a list of fake
findings.

**Reachable undefined behaviour.** Is there an input that divides by this zero
or shifts by this width. Four functions in nine hundred, each with a triggering
input:

| function | property |
|---|---|
| `02_integer_widths::urem64`, `srem64` | `a % b` with `b` unconstrained |
| `17_hash_table::hash_slot` | `% (uint32_t)capacity`, and nothing forces capacity nonzero |
| `54_sha256_block::rotate_right` | `value << (32u - amount)` is undefined at `amount == 0` |

The last is the check validating itself: `rotate_right` is the one function in
this corpus whose undefined behaviour a person had to find by hand, and it is
the single entry the execution differential's known-UB list was created to
hold. Grepping for `<<` finds it among hundreds of safe shifts; asking whether
some input *reaches and breaks* it returns four functions.

Array bounds is the property this does **not** check. The extent lives in the
lowering's `Local` and the LLIR carries an address, not a bound, so by the time
there is a term to ask about, `a[i]` and `*(p + i)` are the same expression.

### Into the knowledge base

`glaurung.llm.kb.source_facts.ingest_source` writes the **infeasible** verdicts
as `source_infeasible_path` nodes with `set_by = "source"`, alongside the
prototypes and dependence edges. Only the infeasible ones: a feasible path is
the ordinary case and one row per path of every function would bury the finding
in its own background. Without a `symbolic` build it writes none, and the
counts say so.

## What this is not

It is not a linter, a type checker, or a code property graph. It reads one
translation unit of C as text and reports numbers about it. It does not resolve
`#include`, does not fold constants, and does not know that two functions with
the same name in different files are different functions.

## Related

* [static C analysis design](../design/static-c-analysis/README.md) — the front
  end these are computed on, and the Joern-parity milestone
* [metrics research](../design/metrics-research/README.md) — the four
  *comparison* metrics, and what each one measures
* [CLI reference](cli.md)
