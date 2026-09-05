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
`.blank_lines`, `.other_lines`, `.source`, `.to_dict()`, and
`.hotspots(by=..., limit=...)` — which raises `ValueError` on an unknown metric
rather than quietly returning source order.

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
                                  [--json | --csv]
                                  [--fail-over METRIC=N ...]
```

Directories are searched recursively for `*.c` and `*.h`. `--csv` writes the
feature matrix with a `path,function,…` header. `--fail-over` is repeatable,
lists every violation on stderr, and **exits 1** — a malformed or unknown metric
exits 2 rather than leaving the gate silently passing.

```console
$ glaurung source-metrics src/ --fail-over cyclomatic=25 --fail-over max_nesting=5
```

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
