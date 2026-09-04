# Decompiler dialects: what each backend emits, and what we recover

> **Kind:** design · **Status:** maintained

The DecBench maintainer's position, verbatim:

> The most important metric to me is CFG Correctness. Joern is the only tool on
> the planet to be able to recover a CFG from uncompilable C (very common in
> decompilation).

He is right that this is the capability that matters. Until this document, our
evidence for it was one-sided: every decompiled artifact in the materialized
tree is Glaurung's own output, and
[`static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §3 already
records that caveat in the S1 gate ("**That second row is weaker than it looks,
and the weakness is the point**"). This document closes it with measurement
against other backends' text.

Two corpora, both real, neither reconstructed:

* **Corpus A --- DecBench's published sample set.** 539 functions, seven
  backends, 3,260 decompiled cells. Ghidra 12.1, IDA 9.20, Binary Ninja 5.3.9757,
  angr 9.2.223, r2dec on r2 6.0.8, dewolf v2026.7.11, kuna 1.121. Each cell also
  carries whether DecBench's published run got a `ged` value for it, which is
  exactly "did Joern-plus-DecBench's-preprocessing recover a CFG here". That
  makes a head-to-head possible on identical inputs.
* **Corpus B --- Ghidra captured locally.** 69 binaries from this repository run
  through Ghidra 12.1.3 PUBLIC headless, 4,287 functions, each tagged with its
  Ghidra symbol name so recovery is measured per function rather than per
  distinct name.

Everything below carries the command that produced it. All numbers in this
document were measured against extension SHA-256 `f5701928dcf1ac69...` at
`master` `73e5375a` **plus** a sibling's uncommitted calling-convention work in
`src/csource/lex/` and `src/csource/parse/decl.rs`, which had landed in that
build. `uv run python tools/build_guard.py` prints the SHA-256 of the extension
you are measuring; if it differs from the one above, re-measure before quoting.

## 1. Joern does not do this alone --- three layers, not one

The bar is not "Joern". It is Joern plus everything DecBench does to the text
first, and there are **three** layers, not the one that is usually cited.

**Layer 1 --- the per-backend adapter, applied before storage.** Only one
backend gets this, and it is the one whose dialect is most famous:
`decbench/decompilers/raw/ida_raw.py::_CODE_REPLACEMENTS` rewrites `__int64` to
`long long`, `_QWORD` to `long long`, `_BYTE` to `char` (and the rest of the
pseudo-type table), and **deletes the substrings** `"__cdecl "`, `"__fastcall "`,
`"__stdcall "`, `"__thiscall "`, `"__usercall "` and `"__noreturn "`. Every other
`raw/*.py` adapter, and `DockerizedDecompiler._normalize_code` (which RetDec
uses), is the identity. So DecBench's `ida` column is *not* Hex-Rays text, and
its `ida` GED numbers say nothing about whether Joern parses genuine IDA output.

**Layer 2 --- `sanitize_decompiled_c`.** `decbench/utils/cfg.py`. Five quirks,
each rewritten "because they break Joern's CDT parser":

| # | quirk | attributed to | what DecBench does |
|---|---|---|---|
| 1 | aggregate/array return type `T [N] name(...)` | angr, ghidra | rewrite to `T name(...)`, line-anchored |
| 2 | ` @ rax` register annotations | binja | strip (`@` is not valid C) |
| 3 | `__int128` | ida | widen to `long long` |
| 4 | computed `goto *EXPR;` | any GNU C emitter | replace with `{}` |
| 5 | raw control bytes inside literals | any backend inlining `.rodata` | hex-escape |

**Layer 3 --- `preprocess_decompiled_c`.** Runs the host `gcc -E` over the
sanitized text when it contains `#define`/`#if`, with a sentinel dance
(`_protect_macro_colliding_definitions`) so a function whose name collides with
a macro survives.

We run **none** of these. `crate::csource::joern::parity_cfgs` calls
`crate::csource::parse::parse(text)` directly on the raw bytes. Layer 2 *is*
ported --- `src/csource/normalize.rs` implements it byte-exactly behind
`Dialect::normalize` --- but nothing calls it on the decompiled side and it is
not exposed to Python. See §6.

## 2. Corpus A --- head to head against Joern-plus-preprocessing

Same 3,260 cells, same text, two front ends. `joern` counts cells where
DecBench's published run produced a `ged` value; `ours` counts cells where
`parity_cfgs` returned a CFG under the function's own name.

| backend | cells | joern | ours (raw) | ours (after layer 2) | joern only | ours only |
|---|---:|---:|---:|---:|---:|---:|
| ghidra | 504 | 501 (99.4%) | **504 (100.0%)** | 504 (100.0%) | 0 | 3 |
| ida | 500 | 496 (99.2%) | **499 (99.8%)** | 499 (99.8%) | 0 | 3 |
| binja | 477 | **473 (99.2%)** | 440 (92.2%) | 440 (92.2%) | 36 | 3 |
| angr | 495 | 493 (99.6%) | **495 (100.0%)** | 495 (100.0%) | 0 | 2 |
| r2dec | 423 | 402 (95.0%) | **417 (98.6%)** | 417 (98.6%) | 0 | 15 |
| dewolf | 347 | **81 (23.3%)** | 52 (15.0%) | 52 (15.0%) | 45 | 16 |
| kuna | 514 | 511 (99.4%) | **514 (100.0%)** | 514 (100.0%) | 0 | 3 |
| **total** | **3,260** | **2,957 (90.71%)** | **2,921 (89.60%)** | 2,921 (89.60%) | 81 | 45 |

```bash
# reads $DECBENCH_DIR/site/data/samples.json (a JSON file; no JVM, no pipeline)
# and calls glaurung._native.csource.parity_cfgs on every cell
uv run python <the probe in this document's history; ~40 lines>
```

Read this carefully, because the aggregate hides the shape:

* **On five of seven backends we already beat Joern-plus-preprocessing**, on
  identical text, with no preprocessing of our own. On ghidra, angr and kuna we
  are at 100%.
* **Applying layer 2 changes nothing for us** --- the sanitized and raw columns
  are identical on all 3,260 cells. Every quirk that layer exists to remove is
  one our parser already tolerates. That is the single most useful fact here:
  the sanitizer is a Joern crutch, not a shared prerequisite.
* **The 81 joern-only cells are two constructs, not a long tail.** 36 binja plus
  45 dewolf; §3 names them.
* **The 45 ours-only cells are mostly r2dec** (15) and dewolf (16) --- cells
  where Joern abstained and we produced a CFG.

Corpus A's `ida` column is layer-1 normalized (§1), so it measures only that
ordinary C parses. §3 covers what Hex-Rays actually prints.

## 3. Per-dialect: what is not standard C, and what we do with it

### 3.1 Ghidra

Ghidra's C output is the best-behaved of the seven. Fixture:
`tests/fixtures/decompiler_dialects/ghidra.c` (all cases captured).

| construct | example | us | notes |
|---|---|---|---|
| `undefined`/`undefined1..8`, `uchar`, `byte`, `code *` | `undefined8 uVar1;` | parses | just undeclared typedef names; a total parser does not care |
| `/* WARNING: ... */` inline analyzer comments | `/* WARNING: Subroutine does not return */` | parses | comments |
| `in_FS_OFFSET`, `stack0x00000008`, `DAT_`/`PTR_`/`FUN_` symbols | `*(long *)(in_FS_OFFSET + 0x28)` | parses | ordinary identifiers |
| `halt_baddata()` | `halt_baddata();` | parses | ordinary call |
| **calling convention in the declarator** | `void processEntry _start(...)` | **gap** | §5.1 |
| **aggregate/array return** | `undefined1 [16] FUN_00108540(void)` | **gap** | layer-2 quirk 1 |
| **`::` in the function name** | `switchD_001011b2::caseD_0(...)` | **gap** | jump-table stubs; Joern's C frontend also fails |
| `__stdcall`, `__cdecl`, `__fastcall` | `HRESULT __stdcall DllCanUnloadNow(void)` | parses | was a gap until the in-flight lexer work landed |

`processEntry` is the one to notice. It is Ghidra's *own* calling-convention
name, so a fix that whitelists the four MSVC keywords does not cover it, and
every ELF executable Ghidra decompiles has one.

### 3.2 IDA (Hex-Rays)

There is no IDA on this machine (`command -v idat64` finds nothing), and
DecBench's stored `ida` column is layer-1 normalized. Fixture:
`tests/fixtures/decompiler_dialects/ida.c` --- three captured cases and **two
reconstructions**, labelled as such in the file.

| construct | us | notes |
|---|---|---|
| `__int64`, `_QWORD`, `_BYTE`, `unsigned __int8` | parses | undeclared typedef names |
| `__int128` | parses | layer-2 quirk 3 is unnecessary for us |
| `__fastcall`, `__cdecl`, `__stdcall` | parses | landed with the in-flight lexer work |
| `__usercall f@<eax>(int a@<ecx>)` | parses | landed with the same work |
| `LODWORD(x)` / `HIDWORD(x)` | parses | ordinary calls |
| **`__spoils<R1,R2,R3,R12,LR>`** | **gap** | §5.2 |

`__spoils` is the only IDA-ism DecBench's layer 1 does not delete, so it is the
only one that actually reaches Joern. It is the single `ida` cell of 500 we lose
(`chibios / ch / dis_func1`) --- and DecBench's published run carries no `ged`
value for that cell either, so **Joern loses it too**. Fixing it closes a gap
against the ground truth, not against Joern.

Worth recording because it is easy to get wrong: layer 1 deletes the string
`"__usercall "` but leaves `@<eax>` in place, and layer 2's `_REG_ANNOTATION`
regex `\s*@\s*[a-z]\w+\b` does **not** match `@<eax>` (the `<`). Neither
DecBench layer removes IDA's register slots; our parser handles them directly.

### 3.3 Binary Ninja

Not installed here (`command -v binaryninja` finds nothing); all four fixture
cases are captured from Corpus A.

| construct | example | us |
|---|---|---|
| `int64_t`/`int128_t`/`uint32_t` sized types, `arg1`/`arg2` names | `int64_t f(void* arg1)` | parses |
| register-named locals (`rax`, `rbx_1`) | `int32_t* rax = ...` | parses |
| `u>>=` unsigned-shift operator spelling | `var_14 u>>= 1;` | parses |
| `label_1:` plus `goto label_1;` | | parses |
| ` @ rax` register annotation | `int64_t f(int64_t arg1 @ rax)` | parses (layer-2 quirk 2 unnecessary) |
| **trailing function attribute** | `void usage() __noreturn` then `{ ... }` | **gap** |

The trailing attribute is **the largest single Joern-versus-us gap in this
whole study**: 33 of our 34 binja losses in Corpus A are `__noreturn` (25) or
`__pure` (8) sitting between the parameter list and the body. It is not valid C
in any dialect --- an identifier where C expects `{`, `;` or a K&R declaration
list --- and DecBench does *not* sanitize it. Joern's CDT front end tolerates it
on its own. The 34th is a C++ symbol carrying a non-ASCII byte in its name.

### 3.4 angr

Captured; all three cases parse.

| construct | us |
|---|---|
| `a0`/`a1` parameters, `vN` locals with `// reg` comments | parses |
| `struct struct_0 { char padding_0[32]; ... }` typedefs ahead of the function | parses |
| `uint128_t`, `unsigned long long` | parses |
| `exit(1); /* do not return */` | parses |
| aggregate return `unsigned long long [4] f(void)` (layer-2 quirk 1, attributed to angr) | parses |

Note the asymmetry with Ghidra: `unsigned long long [4] f(void)` parses for us,
`undefined1 [16] f(void)` does not. The difference is not the return type --- it
is that Ghidra pairs it with an array-typed local `undefined1 auVar1 [16];`.
Both forms are quirk 1 as far as DecBench is concerned.

### 3.5 r2dec

Captured; we recover 98.6% against Joern's 95.0%.

| construct | example | us |
|---|---|---|
| registers used as variables | `eax = *((rbp - 0xc));` | parses |
| memory expressions | `*((rbp - 0x10))--;` | parses |
| dotted r2 flag names in expressions | `rdi = *(obj.stderr);` | parses |
| leading `#include <stdint.h>` that nothing expands | | parses |
| **error text instead of C** | `r2dec has crashed (info: /in/... @ 0x...).` | **not recoverable by anyone** |

6 of 423 r2dec cells are prose, not code. Joern abstains on those too. They are
recorded as a fixture case rather than dropped, so the denominator stays honest.

### 3.6 dewolf

Captured. This is the backend both front ends struggle with, and ours struggles
more: 15.0% against Joern's 23.3%.

| construct | example | us |
|---|---|---|
| doubled return type | `void void usage()` | parses |
| **doubled parameter list** | `long int64_t f(void* a)(void * a){...}` | **gap** |
| **trailing attribute taking a parameter list** | `void void usage() __noreturn(){...}` | **gap** |
| `/* param */` inline argument-name comments | `dcgettext(/* domainname */ 0UL, ...)` | parses |
| `Failed to decompile ... due to ...` prose cells | | not recoverable |

The doubled parameter list is dewolf printing its Binary Ninja signature and
then a C signature, so the declarator has two of them. It is 201 of the 295
dewolf cells we lose --- **and Joern loses 185 of those 201 too.** The genuine
Joern-versus-us gap on dewolf is 45 cells, not 295: 16 of the double-parameter
cases plus the `__noreturn()`/`__pure()` trailing-attribute forms.

### 3.7 RetDec

**Not measurable here.** RetDec is not installed (`command -v retdec-decompiler`
finds nothing), and the published DecBench run on disk has no `retdec` column
--- `samples.json`'s `decompiled` maps and `published_function_results.json`'s
`decompilers` list both omit it, even though
`decbench/decompilers/dockerized.py::RetDecDecompiler` registers the backend.
`tests/fixtures/decompiler_dialects/retdec.c` is therefore **entirely a
reconstruction** and is labelled as one in its header and in every case. It
tests that RetDec's documented shapes (`// Address range:` banners,
`function_<addr>` names, `__asm_*`/`__pseudo_*` intrinsics) parse; it is not
evidence about RetDec.

Worth noting for whoever captures it: RetDec is the one DecBench backend whose
adapter does not normalize, so whatever RetDec prints is what Joern must parse.

## 4. Corpus B --- Ghidra captured locally, by function size

Corpus A's ghidra column is 504 hand-picked benchmark functions. Corpus B is
what Ghidra emits over whole binaries, including the entry stubs, jump-table
stubs and library code a benchmark curates away.

```bash
# DumpDecompiledC.java walks getFunctionManager().getFunctions(true) and prints
# DecompInterface.decompileFunction(f, 60, monitor).getDecompiledFunction().getC()
# behind a "// Function: <name> @ <entry>" marker.
#   NOTE: Ghidra rejects any project path with a dot-prefixed element, so the
#   project directory cannot live under $TMPDIR=$HOME/.cache/glaurung/tmp.
/opt/ghidra/support/analyzeHeadless <projdir> <projname> -import <binary> \
  -scriptPath <scriptdir> -postScript DumpDecompiledC.java <out.c> -deleteProject
```

Ghidra 12.1.3 PUBLIC, openjdk 25.0.4. Wall clock: 6-10 s for a small ELF `.so`,
11-35 s for a 50-300 KB PE, 228 s for a 4 MB static Rust binary.

**9 Windows PE binaries** (`samples/binaries/platforms/windows/vendor/realworld/`
plus a mingw `.exe` and `mathlib.dll`) --- 3,095 functions:

| body size | recovered / total | rate |
|---|---:|---:|
| 1-5 lines | 650 / 650 | 100.00% |
| 6-15 lines | 988 / 1,011 | 97.73% |
| 16-50 lines | 965 / 1,001 | 96.40% |
| 51+ lines | 433 / 433 | 100.00% |
| **all** | **3,036 / 3,095** | **98.09%** |

**60 ELF `.so` from `tests/decompiler_fixtures/build/`** (every 17th, sorted) ---
1,192 functions:

| body size | recovered / total | rate |
|---|---:|---:|
| 1-5 lines | 350 / 358 | 97.77% |
| 6-15 lines | 268 / 285 | 94.04% |
| 16-50 lines | 300 / 316 | 94.94% |
| 51+ lines | 225 / 233 | 96.57% |
| **all** | **1,143 / 1,192** | **95.89%** |

**The rate is not carried by trivial functions.** Of the 4,179 recovered CFGs,
1,429 (34.2%) are single-node, but 1,423 (34.1%) have 8 or more nodes and 528
(12.6%) have 21 or more. Recovery is flat across every size band, and the
*lowest* band in the PE corpus is 16-50 lines, not 1-5.

**Combined: 4,179 / 4,287 = 97.48%.** Restricted to functions whose Ghidra
symbol is a legal C identifier --- dropping the C++/Rust qualified and template
names that Joern's C front end also yields nothing for --- **4,179 / 4,259 =
98.12%**.

Every one of the 108 misses is one of five things:

| n | cause | corpus |
|---:|---|---|
| 30 | `__thiscall` (17 alone, 3 with a qualified name, plus 6+3 in the ELF corpus) | both |
| 24 | aggregate/array return `undefined1 [16] name(...)` | ELF (Rust) |
| 21 | C++/Rust qualified or template name in the declarator | both |
| 10 | `__cdecl` on a C++ symbol | PE |
| 9 | `__rustcall` | ELF (Rust) |
| 1 | implicit-int definition (no return type) | PE |

Timing: 702 us/function on the PE corpus, 1,246 us/function on the ELF corpus,
measured inside the same loop. This is a **debug-profile** extension
(`maturin develop`), so it is an upper bound, not a shipping number.

**A warning about whole-file counting.** `parity_cfgs` is keyed by function
name and keeps one CFG per name (F-15), so counting distinct returned names is
*not* a per-function recovery rate. On a Rust binary this understates badly: a
separate capture of `169_rust_slices_bounds-rustc-O0` has 361 definitions, of
which 299 carry a Rust qualified/template name and 62 have plain C names
resolving to 58 distinct names --- and we return exactly those 58. Measured
per-name that reads as 16%; measured per-function over C-named definitions it is
100%. Corpus B avoids the trap by tagging every function with its Ghidra symbol.

## 5. Where each gap belongs: lexical, syntactic, or a normalization pass

The repo has three places a fix can go, and the choice is not arbitrary.
`src/csource/lex/` decides what is a token; `src/csource/parse/decl.rs` decides
what a declarator may contain; `src/csource/normalize.rs` rewrites text before
either sees it. **Normalization is the last resort**, because it changes the
bytes the parser is measured on and DecBench's own experience is that a text
rewrite silently reshapes what parses --- `normalize.rs`'s own module docs say
exactly that.

### 5.1 Syntactic --- the declarator's specifier list (`parse/decl.rs`)

`processEntry`, `__thiscall`, `__rustcall`, `__regparm3` and IDA's `__spoils<...>`
are all the same shape: **an identifier between the return type and the function
name**. So were `__cdecl`/`__stdcall`/`__fastcall`/`__usercall`, which the
in-flight lexer/parser work has now fixed.

The recommendation is explicit: **do not extend a keyword whitelist.** Across
Corpus B's 4,287 captured functions Ghidra printed five distinct ones in that
position --- `__rustcall` (436), `__cdecl` (320), `__thiscall` (59), `__stdcall`
(10), `processEntry` (6), counted with
`grep -hoE '^[A-Za-z_][A-Za-z0-9_ *]*[ *](__[a-z]+|processEntry) ' <captures>`
--- and it will emit any convention name a processor spec defines, so the set is
open. The rule that
covers all of them, and is what CDT effectively does, is: **in a function
definition's declaration specifiers, an identifier that is followed by another
identifier (rather than by `(`, `*`, `,`, `;` or `)`) is a specifier, not the
declarator.** That is a `parse/decl.rs` change, not a lexer change; the lexer
already produces the right tokens.

`__spoils<R1,R2,R3,R12,LR>` needs one extra rule on top: a balanced `<...>` run
after such a specifier is part of it. That is deliberately narrow --- it must not
apply in expression position, where `<` is less-than.

### 5.2 Syntactic --- the trailing function attribute (`parse/decl.rs`)

Binary Ninja's `void usage() __noreturn { ... }` and dewolf's
`void void usage() __noreturn(){ ... }` are the **largest** remaining gap and
belong in the same file. After a function declarator's parameter list, C expects
`{`, `;`, or a K&R declaration list. The recovery rule is: **an identifier there
(optionally followed by a balanced parenthesised group) is an attribute; skip it
and keep looking for the body.** That covers `__noreturn`, `__pure`, `__const`
and dewolf's `__noreturn()` form in one rule, and it is a recovery rule, so it
cannot change how well-formed C parses.

This is where the maintainer's claim is actually being tested, and today Joern
wins it: 33 binja cells plus the dewolf attribute cells.

### 5.3 Syntactic --- implicit-int definitions (`parse/decl.rs`)

`f(int a, int b) { ... }` with no return type is C89-legal and Ghidra emits it
when it cannot determine one. It is one function in 4,287 captured, so it is
low-priority --- but it is a *language* rule, so it belongs in the parser, and it
interacts with §5.1: once an identifier may be a specifier, "no specifier at
all" has to be distinguishable from "the specifier is the name".

### 5.4 Semantic, and out of scope for the C front end

**`::` in a function name.** Ghidra's jump-table stubs
(`switchD_<addr>::caseD_<n>`, `switchD_<addr>::default`), C++ methods, Rust
paths. This is not a C dialect quirk; it is C++ text. Joern's own C front end
returns zero functions for C++ input --- DecBench documents this in
`temp_parse_suffix`, which routes `.ii` to Joern's C++ front end precisely
because the C one "silently scores nothing". Fixing it means either a C++ name
grammar or a pre-parse name mangling, and it should be argued on its own terms,
not smuggled in as a dialect fix. 21 of the 108 Corpus B misses and 3 of the 26
fixture cases sit here.

**Aggregate/array return type `T [N] name(...)`.** 24 of the 108 Corpus B
misses, all Rust `undefined1 [16]`. This one is a genuine judgement call:

* As a *parser* rule it is ugly. `T [N] name(...)` is not a C declarator under
  any reading; making it one risks mis-parsing a real declaration.
* As a *normalization* rule it is one line, it is already written and tested
  byte-exactly (`normalize.rs::sanitize_decompiled_c`, `_AGG_RETURN`, anchored
  to line start so an in-body `char buf[16];` is untouched), and it is what
  DecBench itself does.

The recommendation is **normalization**, and specifically: wire
`Dialect::Decompiled(text).normalize()` into the decompiled-side path and expose
it to Python, rather than adding a sixth ad-hoc rewrite. See §6.

**Prose cells.** r2dec crash messages, dewolf "Failed to decompile ...". Not
recoverable by anyone. They belong in the denominator and in the fixture set,
and nowhere else.

## 6. `normalize.rs` is written, ported, tested --- and never called

`src/csource/normalize.rs` is a byte-exact port of DecBench's layer 2, gated
behind `Dialect::Preprocessed` / `Dialect::Decompiled` so a caller cannot
sanitize ground truth by accident. `crate::csource::joern::parity_cfgs` does not
call it, and `src/python_bindings/source_cfg.rs` does not expose it.

Corpus A says that is currently costing us **nothing**: raw and sanitized
recovery are identical on all 3,260 cells (§2). But that is a statement about
this corpus, and the four measured aggregate-return misses in Corpus B are
exactly the case layer 2 exists for. Two things should happen, in this order:

1. **Expose `Dialect::normalize` to Python** so a caller can measure with and
   without it. It is currently impossible to reproduce §2's "after layer 2"
   column without reimplementing the sanitizer in Python.
2. **Decide, with a measurement, whether the decompiled-side path should call
   it.** The argument for is quirk 1. The argument against is that every number
   in the S3 parity work was measured on raw text, and turning on a text rewrite
   under a 93.1636% parity figure without re-measuring is the kind of change
   `docs/development/traps.md` exists to prevent.

## 7. What this does and does not establish

**Establishes.** On 3,260 cells of six other decompilers' real output, our C
front end recovers 89.60% of functions against Joern-plus-DecBench's-three-
preprocessing-layers' 90.71%, beating it on five of seven backends and matching
100% on three. On 4,287 functions of locally captured Ghidra output it recovers
97.48% (98.12% over C-named definitions), flat across function sizes, with 108
misses in five named classes. Layer 2 of DecBench's preprocessing is unnecessary
for us on every cell measured. A function we cannot parse never costs its
neighbours --- asserted per fixture in
`python/tests/test_decompiler_dialects.py`.

**Does not establish.** Nothing about RetDec (§3.7). Nothing about genuine
Hex-Rays text at scale --- Corpus A's `ida` column is layer-1 normalized and the
two raw cases in the fixture are reconstructions. Nothing about *CFG shape*: this
document measures whether a function is recovered at all, which is the
precondition for GED, not GED itself. And nothing about C++ input, where Joern's
C front end and ours both yield nothing.

**Reproduce.**

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
uv run python tools/build_guard.py          # record the extension SHA-256 first
uv run pytest python/tests/test_decompiler_dialects.py -q
```

## 8. Pointers

* `tests/fixtures/decompiler_dialects/` --- 26 cases across 7 backends, each
  declaring `provenance:` (`captured` or `RECONSTRUCTION`), `source:`, `expect:`
  and, for a gap, `gap:`. 22 captured, 4 reconstructions (2 IDA, 2 RetDec).
* `python/tests/test_decompiler_dialects.py` --- asserts every case, both
  directions, plus a `KNOWN_GAPS` ledger that fails when a gap closes.
* [`../static-c-analysis/roadmap.md`](../static-c-analysis/roadmap.md) §3 --- the
  one-sided-evidence caveat this document answers.
* [`../static-c-analysis/joern-behavior.md`](../static-c-analysis/joern-behavior.md)
  --- Joern's own loss rates, measured.
* `src/csource/normalize.rs` --- the ported layer 2, and §6's open question.
