# Error recovery: ours, clang and tree-sitter on broken decompiler C

> **Kind:** design · **Status:** maintained

The DecBench maintainer's claim, verbatim:

> Joern is the only tool on the planet to be able to recover a CFG from
> uncompilable C (very common in decompilation).

[`decompiler-dialects.md`](decompiler-dialects.md) answers the *undamaged* half
of that: on DecBench's own 3,260 stored cells our front end recovers 89.60% to
Joern's 90.71%, and on five of seven backends we are ahead. This document
answers the other half, which nobody had measured: **what happens when the C is
not merely untypeable but syntactically broken.**

That distinction is the whole point. Ghidra emits *syntactically well-formed* C
that uses undefined types; tolerating that is easy, and any parser that skips
type resolution gets it for free. Truncation, unbalanced braces, raw `.rodata`
bytes and overlapping definitions are the hard claim, and they are what this
harness manufactures on purpose.

- **Harness:** [`tools/parser_recovery_bench.py`](../../../tools/parser_recovery_bench.py)
- **Tests:** [`python/tests/test_parser_recovery.py`](../../../python/tests/test_parser_recovery.py)
  (58 tests, `core`) and
  [`python/tests/test_parser_recovery_decbench.py`](../../../python/tests/test_parser_recovery_decbench.py)
  (1 test, `decbench`, deselected by default). The split is not cosmetic:
  `tools/gen_test_facets.py` classifies by whole-file text match, so leaving the
  one test that reads the DecBench checkout beside the others tagged all 59
  `decbench` and `pytest.ini` deselected every one of them -- 59 tests that
  appeared to pass while contributing nothing.

## 1. What was compared, and what could not be

| parser | how it was run | status |
|---|---|---|
| **ours** | `glaurung._native.csource.parity_cfgs` -- the production entry point DecBench's GED column uses | measured |
| **clang** | libclang 21, `PARSE_INCOMPLETE \| CXTranslationUnit_KeepGoing`, `-std=gnu11 -ferror-limit=0 -w -nostdinc` | measured |
| **tree-sitter** | `tree_sitter_c` via `tree_sitter` 0.26.0 | measured |
| **Eclipse CDT** (Joern's parser) | needs a JVM this harness never starts | **not measured -- inferred only, see §7** |

Decompilers whose output would have widened the corpus and could not be run
here: **r2dec** (needs radare2, not installed), **dewolf** (needs a commercial
Binary Ninja licence), **kuna** (not public), **RetDec** (not installed). We
compared against the decompilers we could actually run. Their absence matters
for exactly one reason: `decompiler-dialects.md` measured Joern at **23.3%** on
dewolf, which is the largest known exception to the "only tool on the planet"
claim, and nothing here either confirms or extends that.

## 2. The metric, and why it is this one

Three parsers that fail in three different ways cannot share a single number.
tree-sitter *always* returns a tree, so "did it parse" is meaningless for it.
clang returns an AST plus diagnostics and will happily call a function a
definition whose body it threw away. Our front end returns CFGs and no error
channel at all.

So the harness scores four things, and only the first two are directly
comparable across parsers.

| metric | definition | comparable across parsers? |
|---|---|---|
| **recall** | ground-truth function definitions recovered with a **non-empty body**: an entry in `parity_cfgs` with nodes and not degenerate (ours); a `FUNCTION_DECL` that `is_definition()` whose `COMPOUND_STMT` has at least one child (clang); a `function_definition` whose body has at least one named child (tree-sitter) | **yes** -- a name is a name |
| **localization** | recall restricted to functions the damage never touched. This is the load-bearing one: it asks whether one broken function poisons the rest of the file | **yes** |
| **fidelity** | of the intact functions, how many the parser recovered with a body structure **byte-identical to its own parse of the undamaged file**. Catches a parser that returns the name but silently loses statements | within a parser, across damage classes; only loosely across parsers (see below) |
| **error-free** | the parser's own "no error here" signal: not degenerate (ours), no error diagnostic inside the extent (clang), no `ERROR`/missing node in the body (tree-sitter) | **no** -- three different signals |

Recall is the metric the brief proposed, and it survives scrutiny: it is the
only definition all three tools can be judged on identically. Fidelity is the
addition, because recall alone cannot tell a parser that recovered a function
from one that returned its name over a body it mangled -- and a wrong CFG is
worse than a missing one for GED.

**Fidelity's cross-parser caveat, stated plainly.** Each parser is compared only
to *itself* on the undamaged text, but the signatures differ in granularity: ours
is the parity CFG (`nodes`, `edges`, `entry`, `exit`) after chain contraction,
which is *coarser* than clang's cursor-kind multiset or tree-sitter's node-type
multiset. A straight-line function is one CFG node for us and a dozen AST nodes
for them. Our fidelity number is therefore easier to satisfy, and the comparison
is about direction, not decimal places. It is still the right signature for this
question: the parity CFG is the artifact DecBench actually scores.

**`error-free` is not a scoreboard.** Ours reads 100% everywhere because
`parity_cfgs` has no per-function error channel to report through -- that is a
limitation of ours, not a win, and it means our front end can hand back a
confidently wrong CFG with nothing saying so. clang's reads 9-31% because on
decompiler output its errors are overwhelmingly *semantic* (`unknown type name
'undefined8'`) and its severity gives no way to separate those from broken
syntax. The column is in the report because hiding it would be worse; do not
read it as a ranking.

## 3. The corpus

Two real decompilers over one binary set, so the same functions are seen twice
through different dialects.

| corpus | producer | provenance |
|---|---|---|
| **ghidra** | Ghidra 12.1.3 `analyzeHeadless` + `DumpC.java` | 13 captures under `~/glaurung-ghidra/out/` |
| **angr** | angr 9.3.4, `CFGFast(normalize=True)` + `analyses.Decompiler` per function, run here | 352 functions from the 12 binaries that have a Ghidra capture, cached to `~/.cache/glaurung/parser-recovery/angr-units.json` |

Both are the fixture binaries in `tests/decompiler_fixtures/build/`. angr is one
of DecBench's thirteen decompiler columns, so its recovery rate is directly
relevant rather than incidental.

Units are concatenated into translation units the way DecBench itself does --
`// Function: <name>` markers, four functions per case -- because that is the
shape Joern is actually handed (`decbench/utils/cfg.py`). Ground truth is the
declarator in the text, read by the harness's own line scanner, never by a
parser under test.

Damage is applied to exactly one function per case, never the first, so every
case has intact functions before and (except under truncation) after the break.

| class | operators | why it is real |
|---|---|---|
| **1 pristine** | none | the control: real decompiler output, byte for byte |
| **2 dialect** | `__fastcall`/`__cdecl`/`__stdcall`; `__usercall f@<eax>`; binja `long x @ rax`; Ghidra `undefined1 [8] f(void)`; `__int128`/`_QWORD` | four of the five constructs DecBench's sanitizer rewrites |
| **3 gnu** | `goto *expr` with `&&label`; statement expression, `__typeof__`, `__attribute__` | the fifth sanitizer rule, plus GNU C decompilers emit |
| **4 truncated** | cut after the body `{`, after a statement, mid-expression | a decompiler killed mid-write, or a truncated capture |
| **5 garbage** | raw `.rodata` bytes as code; control bytes inside a literal; interleaved disassembly and log lines | verbatim `.rodata` inlining, and stream contamination |
| **6 structural** | delete a `}`; insert a stray `}`; delete a `)`; start the next function's header inside this one | an unmatched region from a structurer, and the concatenation shape DecBench itself builds |

Every choice is seeded (`--seed 20260904` throughout) and recorded in the report
header. A parser that crashes or hangs is a result: each call runs in a separate
interpreter with a 30-second budget, and a timeout kills the worker rather than
the run. There were **zero timeouts and zero crashes** in every cell below.

The isolation is a subprocess and not a forked worker for a measured reason: the
first version of the runner forked from a multi-threaded pytest process, and a
child inherited a held lock. Both processes sat at 0% CPU for twenty minutes,
which reads as "slow parser", not as a bug. `test_isolated_runner_records_a_hang_rather_than_hanging`
bounds itself on a thread so that failure mode fails the suite instead of
hanging it.

## 4. The matrix

Two configurations, because 7 of the 13 captured binaries are Rust and Rust
output is a different population from C output. `all binaries` is the honest
whole; `C-only` drops every stem matching `rust` and is the number to read if
you care about C programs.

Commands, run 2026-09-04:

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"
uv run python tools/parser_recovery_bench.py capture-angr
uv run --with clang --with tree_sitter --with tree_sitter_c \
  python tools/parser_recovery_bench.py run \
  --cases-per-source 40 --max-per-binary 16 --functions-per-case 4
uv run --with clang --with tree_sitter --with tree_sitter_c \
  python tools/parser_recovery_bench.py run \
  --cases-per-source 40 --max-per-binary 16 --functions-per-case 4 \
  --exclude-binary rust
```

**The build measured:** `uv run maturin develop --release` at commit
`a98f3af4` ("csource: parse the dialects real decompilers emit"), **clean
working tree** -- `src/csource` and `src/metrics` both unmodified, as the report
header records. Release profile; `maturin develop` without `--release` is a
debug build and its numbers are not these.

The same matrix was produced twice: once at `9c848ac9` with that dialect work
still uncommitted in the tree (`git patch-id`
`330e6853b5aea233501fa96f8481b5b753c7de23`), and once at `a98f3af4` after it
landed. **Every cell is byte-identical between the two runs** -- so class 2
below measures the landed dialect support, and the working-tree version it came
from recovered exactly the same functions.

### 4.1 All binaries -- 1,404 cases, 40 base groups per corpus

Percentages are `recovered / total`; the parenthesised counts are the real ones.

| corpus | class | ours | clang | tree-sitter |
|---|---|---|---|---|
| angr | 1 pristine | **91.9%** (147/160) | 56.2% (90/160) | 90.0% (144/160) |
| angr | 2 dialect | **92.5%** (718/776) | 49.7% (386/776) | 80.9% (628/776) |
| angr | 3 gnu | **91.9%** (294/320) | 56.2% (180/320) | 90.0% (288/320) |
| angr | 4 truncated | **65.6%** (315/480) | 37.1% (178/480) | 55.2% (265/480) |
| angr | 5 garbage | **91.9%** (441/480) | 55.8% (268/480) | 89.8% (431/480) |
| angr | 6 structural | **89.6%** (502/560) | 49.8% (279/560) | 87.9% (492/560) |
| ghidra | 1 pristine | **93.8%** (150/160) | 88.8% (142/160) | 89.4% (143/160) |
| ghidra | 2 dialect | **93.4%** (747/800) | 80.5% (644/800) | 78.1% (625/800) |
| ghidra | 3 gnu | **93.8%** (300/320) | 90.0% (288/320) | 88.8% (284/320) |
| ghidra | 4 truncated | **70.0%** (336/480) | 58.5% (281/480) | 57.1% (274/480) |
| ghidra | 5 garbage | **93.8%** (450/480) | 87.9% (422/480) | 89.0% (427/480) |
| ghidra | 6 structural | **93.8%** (540/576) | 82.5% (475/576) | 89.6% (516/576) |

Localization -- the "did the break stay local" number -- and fidelity:

| corpus | class | ours loc / fid | clang loc / fid | tree-sitter loc / fid |
|---|---|---|---|---|
| angr | 4 truncated | **89.6%** / 100.0% | 55.8% / 100.0% | **89.6%** / 100.0% |
| angr | 6 structural | **89.1%** / 97.5% | 46.1% / 88.7% | 87.5% / **98.6%** |
| ghidra | 4 truncated | **94.8%** / 100.0% | 92.2% / 100.0% | 92.2% / 100.0% |
| ghidra | 6 structural | **92.6%** / 99.7% | 81.2% / 89.3% | 90.1% / **100.0%** |

### 4.2 C-only -- 577 cases, `--exclude-binary rust`

| corpus | class | ours | clang | tree-sitter |
|---|---|---|---|---|
| angr | 1 pristine | **100.0%** (56/56) | **100.0%** (56/56) | **100.0%** (56/56) |
| angr | 2 dialect | **100.0%** (280/280) | 90.7% (254/280) | 90.7% (254/280) |
| angr | 3 gnu | **100.0%** (112/112) | **100.0%** (112/112) | **100.0%** (112/112) |
| angr | 4 truncated | **73.8%** (124/168) | 66.1% (111/168) | 63.1% (106/168) |
| angr | 5 garbage | **100.0%** (168/168) | 98.8% (166/168) | **100.0%** (168/168) |
| angr | 6 structural | 99.0% (194/196) | 92.3% (181/196) | **100.0%** (196/196) |
| ghidra | 1 pristine | **100.0%** (76/76) | 98.7% (75/76) | **100.0%** (76/76) |
| ghidra | 2 dialect | **100.0%** (380/380) | 88.7% (337/380) | 86.6% (329/380) |
| ghidra | 3 gnu | **100.0%** (152/152) | 98.7% (150/152) | **100.0%** (152/152) |
| ghidra | 4 truncated | **71.1%** (162/228) | 62.7% (143/228) | 61.0% (139/228) |
| ghidra | 5 garbage | **100.0%** (228/228) | 98.2% (224/228) | **100.0%** (228/228) |
| ghidra | 6 structural | **100.0%** (272/272) | 90.1% (245/272) | **100.0%** (272/272) |

Class 4's ceiling is below 100% by construction -- truncation deletes the
functions after the cut, and no parser can recover text that is not there. The
ceiling is identical for all three, so the column is still a fair comparison;
it is the *localization* row that says whether the surviving prefix was
recovered, and there we are at 100.0% on C-only for both corpora.

## 5. Where we lose

Stated without softening.

**5.1 tree-sitter beats us on structural damage in clean C.** On the C-only
angr corpus, class 6, tree-sitter recovers 196/196 and we recover 194/196.
Both lost functions come from one operator, `drop_close_paren`, and the
construct is exact:

```c
unsigned long long * _init(void      <-- one ')' deleted from the header
{
    ...
}
```

An unclosed parameter list **in a definition header** costs us the function
*and* its successor: we returned `__do_global_dtors_aux` and `_fini` and lost
both `_init` and the `deregister_tm_clones` that follows it. tree-sitter
resynchronizes at the body's `{` and keeps all four. This is our only remaining
structural-recovery gap on well-formed-ish C, it is a two-function loss out of
196, and it is precisely actionable: recover at the `{` when a declarator's
parameter list never closes.

**5.2 tree-sitter beats us on fidelity under structural damage.** On all
binaries, class 6: 98.6% vs our 97.5% (angr) and 100.0% vs our 99.7% (ghidra).
We keep more functions; tree-sitter keeps more *unchanged* functions. Nine
intact angr CFGs and one intact Ghidra CFG changed shape because of a break
elsewhere in the file. For a GED column that is a wrong score, not a missing
one, and it is the worse failure of the two.

**5.3 Nothing recovers Ghidra's Rust output, us included.** On all binaries our
class-1 recall is 93.8% (ghidra) and 91.9% (angr) rather than 100%, and every
loss is Rust. Ghidra prints, in a file it calls C:

```c
i32 __rustcall _166_rust_generics::166_rust_generics::rust_generic_i32(i32 v,u32 n)
{
  iVar1 = fold_generic<i32>(v,n & 0xf);
```

A qualified name whose middle component **begins with a digit**, an open-set
calling convention (`__rustcall`), and template syntax in a call. All three
parsers lose it. We lose 23 functions of 1,280 undamaged ones, tree-sitter
loses 33, clang loses 88.

**5.4 Truncation is the class everyone is worst at**, and we are only first
among three: 70.0%/65.6% recall on all binaries. The intact prefix is
recovered fully (94.8%/89.6% localization, 100% fidelity), so the deficit is
the deleted tail rather than a recovery failure -- but a real pipeline that
truncates output loses those functions regardless of whose parser reads it.

## 6. What "semantic tolerance is easy" actually costs clang

The brief's premise was that undefined types are the easy case. Measured, they
are not easy for clang -- they are *silently lossy*, which is worse than a
refusal. Three shapes, all syntactically valid C, asserted in
`test_clang_discards_the_body_of_an_untypeable_function`:

| input | clang | ours | tree-sitter |
|---|---|---|---|
| `undefined8 f(undefined8 a) { undefined8 r; r = g(a); return r; }` | `FUNCTION_DECL` **with an empty `COMPOUND_STMT`** -- the whole body is gone | 1 CFG node | 12 body nodes |
| `void f(void) { undefined8 r; r = g(); return; }` | body kept, but **only the `return` survives** | 1 CFG node | 10 body nodes |
| `int f(int a) { undefined8 r; r = g(a); return 0; }` | 2 nodes: `undefined8 r;` and `r = g(a);` **dropped** | 1 CFG node | 12 body nodes |

clang still reports `is_definition()` as true in all three. A CFG built from
that AST is wrong and nothing in the AST says so. This is why clang's recall
collapses on angr's Rust output (56.2% at class 1) while its recall on Ghidra's
C stays near 90%: Ghidra names its unknown types in the return position rarely,
angr does it constantly.

## 7. The CDT column: what it can and cannot claim

Eclipse CDT was **not run**. Nothing in this document is a measurement of
Joern's parser.

What is measurable without a JVM is DecBench's own
`sanitize_decompiled_c`, whose docstring says it exists to "clean
decompiler-specific C quirks that break Joern's parser" and which rewrites five
constructs: Ghidra's aggregate return `T [N] name(...)`, binja's `@ rax`,
`__int128`, computed `goto *expr;`, and raw control bytes in literals. Its
comments are explicit about the cost -- of the aggregate return: "Joern parses
nothing for such a function and it silently drops out of GED's denominator."

Counting the cases DecBench must rewrite is therefore a **lower bound on
constructs CDT could not take raw**, asserted by its authors, not by us:

| corpus | class | cases DecBench rewrites (all binaries) | (C-only) |
|---|---|---:|---:|
| angr | 1 pristine | 5 | 3 |
| angr | 2 dialect | 130 | 48 |
| angr | 3 gnu | 45 | 17 |
| angr | 4 truncated | 12 | 6 |
| angr | 5 garbage | 50 | 20 |
| angr | 6 structural | 16 | 12 |
| ghidra | 1 pristine | 1 | 0 |
| ghidra | 2 dialect | 122 | 57 |
| ghidra | 3 gnu | 41 | 19 |
| ghidra | 4 truncated | 3 | 0 |
| ghidra | 5 garbage | 42 | 19 |
| ghidra | 6 structural | 3 | 0 |

**What this can claim:** DecBench's authors judged these rewrites necessary
before CDT, and five of our angr class-1 cases -- *undamaged* angr output --
already trip them. **What it cannot claim:** any recall, localization or
fidelity number for CDT, or that CDT would fail on a rewritten case, or that it
would fail on an unrewritten one. A sanitizer rule is evidence of a *belief*
about a parser, not a measurement of it. Pair this with
`decompiler-dialects.md` §"three preprocessing layers", which found that
DecBench's IDA adapter *deletes* `__cdecl`/`__fastcall`/`__stdcall`/`__usercall`
before storage -- so the published `ida` column says nothing about CDT parsing
genuine Hex-Rays text either.

Our own column needs no such footnote: applying `sanitize_decompiled_c` to our
input changed our result on zero of DecBench's 3,260 stored cells
(`decompiler-dialects.md`).

## 8. What real decompiler output actually contains

Counted over the undamaged cases, so nothing here is injected.

| construct | angr (all / C-only) | ghidra (all / C-only) |
|---|---|---|
| `::`-qualified declarator | 22 / 0 | 7 / 0 |
| `<` or `>` in a declarator | 25 / 2 | 14 / 3 |
| computed `goto *` | 5 / 3 | 0 / 0 |
| aggregate return `T [N] name(` | 0 / 0 | 1 / 0 |
| `@` register annotation | 0 / 0 | 0 / 0 |
| `__int128` | 0 / 0 | 0 / 0 |
| raw control byte outside a literal | 0 / 0 | 0 / 0 |

Two things follow. First, **computed `goto` is not hypothetical**: angr emits
`goto *((void *)(g_404010));` on its own, in three C-only cases, with no
prompting. Second, angr on Rust binaries emits type syntax that is not C at
all:

```c
: &u64 _init(void)          /* the return type is ": &u64" */
{
    v1: &u64;               /* Rust-style declaration */
```

```c
u32 _166_rust_generics::max_generic(*u8 a0, a1: u64)
{
    v11: u128;  // xmm2
```

```c
extern _ZN3std3sys4unix4args3imp4ARGC17h862db46850e77126E.0: u64;
```

A `.` inside an identifier, `*u8` as a type, `name: type` declarations, `u128`.
This is the population the maintainer's claim is about, and it is the reason
the harness takes ground truth from the declarator in the text rather than from
angr's symbol table -- angr's `Function.name` is the *mangled* symbol
(`_ZN18_166_rust_generics11max_genericE...`) while its codegen writes the
demangled one. Using the symbol table scored every parser 52.5% on undamaged
output for a naming mismatch none of them caused.

## 9. Threats to validity

- **Sample size.** 40 base groups per corpus, four functions each; 1,404 cases
  all-binaries and 577 C-only. A one-function difference is 0.2-0.6 points on
  most cells, so differences under a point are noise. The two-function
  `drop_close_paren` loss in §5.1 is named by case and construct rather than
  left as a rate for that reason.
- **13 binaries, one architecture, one toolchain family.** These are the
  `tests/decompiler_fixtures/` ELFs; nothing here is PE, Mach-O or non-x86-64.
- **One `.so`, one machine.** All three parsers ran on the same box against
  one release build; nothing here is a cross-machine or cross-version claim.
- **Damage is synthetic for classes 4-6.** No decompiler emits truncation on
  demand. Classes 1-3 are real output (classes 2-3 are real constructs spliced
  into real output); classes 4-6 are manufactured, seeded, and reproducible,
  and they are the only route to the adversarial cases.
- **Ours has no error channel**, so `error-free` flatters it (§2).
- **Fidelity signatures differ in granularity** across parsers (§2).
- **CDT is inferred, not measured** (§7).
