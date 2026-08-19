# Decompiler roadmap — execution diary, 2026-08-19

Continues [the 2026-08-18 diary](decompiler-roadmap-diary-2026-08-18.md).
Entry numbering is continuous across files.

## Entry 80 — a formatter told to target a Python we do not require

`pyproject.toml` line 7 declared `requires-python = ">=3.11"`. Line 95, under
`[tool.ruff]`, said `target-version = "py314"`.

Ruff does what it is told. Its formatter rewrote `except (A, B):` into PEP 758's
unparenthesized `except A, B:` — syntax that landed in **Python 3.14** — at six
sites across the two files that gate the corpus:

```
tools/fitness_report.py:487      except OSError, json.JSONDecodeError:
tools/diff_decompile.py:604,620  except TypeError, ValueError:
tools/diff_decompile.py:852      except OSError, RuntimeError, ValueError:
tools/diff_decompile.py:2376     except OSError, json.JSONDecodeError:
tools/diff_decompile.py:2397     except json.JSONDecodeError, IndexError:
```

Both files were a **SyntaxError on every interpreter the project claimed to
support**, and parsed only on the one pinned here.

### How it was found is the part worth keeping

I found the first instance by hand, fixed it, and moved on. **Ruff put it
straight back on the next `uvx ruff format`.** That is what pointed at the
config rather than the code — a source-only fix would have survived exactly
until someone ran the documented command.

A defect that repairs itself back into existence is a configuration defect
wearing a code defect's clothes. The tell is that fixing it twice produces the
same diff.

### The bump was measured, not assumed

The user suggested `>=3.12` and guessed DecBench was the constraint. Measured:

```
for f in $(git ls-files '*.py'); do python3.11 -c "ast.parse(open('$f').read())"; done
```

After the six fixes, **all 866 tracked files parse on 3.11**. No
`sys.version_info` guard exists anywhere in `python/` or `tools/`. The decbench
tools carry no version pin and all parse on 3.11. So the floor was a policy
choice with nothing behind it, and 3.12 is free. Both settings now track each
other with the incident recorded on the ruff line.

### And the tree had not been formatted in a long time

`uvx ruff format --check` reported **338 files dirty at HEAD**, before this
session touched anything. That is why the misconfiguration survived: the command
that would have exposed it was in `CLAUDE.md` and not in anyone's loop.

Reformatting them is now its own commit — 325 files, one lint fix, isolated so
the six lines that mattered are not buried in it.

## Entry 81 — the gate that could not see it, and the one that took the shell down

Two failures in one run, and they needed opposite responses.

### A regression `cargo test` structurally could not see

The scalar-to-lane XMM mirror changed what `movsd xmm0, xmm1` lifts to. A test
asserted the old single-`Assign` shape and broke.

`cargo test --features python-ext` was **green throughout** — 2,667 with the
mirror applied, 2,676 two changes later — because that assertion lives in
`python/tests/test_ir.py` and exercises the binding, not the Rust. The only gate
that covers it is the full Python suite, which takes ~14 minutes and is not in
the fast loop.

The test was stale, not the code: `movsd xmm, xmm` preserves bits 64..127, so
defining exactly lanes 0 and 1 is correct. It is rewritten to pin the shape
**and the reason**, including asserting the *absence* of `_d2`/`_d3` so the
register form's preservation semantics cannot later be widened into the memory
form's by accident.

The general point: **a change to the lifter can only be validated by whichever
suite happens to assert on it**, and those two suites have very different cycle
times. A fast green is not evidence about the slow one.

### The tmpfs filled and took Bash down entirely

Three other failures in the same run were `sqlite3.OperationalError`. Then every
Bash command started returning a bare `Exit code 1` — including `echo alive`
and `ls`.

Nothing was wrong with the commands. The tool writes `pwd -P >| /tmp/claude-…`
after each invocation, and that write was failing:

```
/bin/bash: line 9: pwd: write error: Disk quota exceeded
```

**The Read tool still worked**, because it does not go through that wrapper —
reading the last background job's output file is what surfaced the real error.

The cause was 49 GB across 57 finished agent worktrees, ~1 GB each even after
`target/` was gone. Removing them wholesale (`git worktree remove --force`,
skipping the one agent `ListAgents` reported live) took it to 1.1 GB and 477 GB
free.

This is the third distinct form of the same failure recorded in this project:
`/tmp` scratch (2026-08-13, 663 abandoned dirs, 13 GB), agent `target/`
directories (2026-08-17, 490 GB), and now the worktree source trees themselves.
Each time it surfaced as something else — a plausible assertion failure, then
236 fake fixture failures, and this time **942 "infrastructure errors" and 18
bogus `pass -> nonportable` verdicts** in a subagent's run that were clean when
re-run. Infrastructure exhaustion never announces itself.

## Entry 82 — three causes where I said one, and two of them were not about struct returns

The callee side of aggregate returns. I filed it as seven cells with one cause —
the callee's own `IntegerPair` contract, diagnosed from `bv195_make_quad`
computing four members and returning one eightbyte.

`baseline.json` records **eight**, and the agent found **three** causes:

```
cell                                cause
195:{gcc,clang}:O0:bv195_make_quad    A
195:{gcc,clang}:O2:bv195_make_quad    A + B
195:gcc:O2:bv195_make_pair            B alone
198:gcc:O2:agr198_make_trio           A + C
198:clang:O2:agr198_make_trio         A + B
198:gcc:O2:agr198_make_bytes3         C alone
```

**Cause A** was mine and confirmed: `declared_return_class` already answered
`IntegerPair` and nothing consumed it on the callee side, so the signature fell
back to one machine word and `rdx`'s definition was dead-store eliminated.

**Cause B has nothing to do with struct returns.** `Mnemonic::Lea` ended in a
raw `Op::Assign` and never appended the 32-bit-destination `ZExt` that every
other x86 ALU form gets from `emit_machine_bin_with_flags`. So
`lea edx,[rdi+rdi*1]` at `seed == -1` produced `0x1_0000_0000` and the stray bit
landed in the next member. `add edi,0x2` in the same function rendered correctly
— it goes through the ZExt path. **A general 32-bit truncation defect in the
lifter**, and a returned aggregate is merely the only shape in the corpus that
reads the affected bits.

**Cause C is also not about struct returns.** A stack load wider than the slot
it starts in was rewritten to the first slot's name, dropping its neighbours —
`mov [rsp-0x14],eax ; mov [rsp-0x10],eax ; mov rax,[rsp-0x14]`. It is why
`162_unaligned_memcpy_access:i386:O0:ua162_store_be32` also moved.

**Two of eight cells had nothing to do with the thing I filed.** A cluster
picked out by a symptom is not a cause, and this is the second time in two days
that measuring the split refuted a "single mechanism" claim of mine — the first
was 22 of 70 float cells.

### And the corpus was hiding the scale

`extract_dwarf_signatures_path` **silently drops any function whose return
aggregate contains a float member, an array member, or is a union.** It emits 6
signatures for fixture 197 and none of the `hfa197_make_*`; it drops
`bv195_make_mixed`, `bv195_make_big`, `agr198_make_arr2`, `agr198_make_bits`.
Those cells read `structural` with the detail *"signature not recoverable from
DWARF"* — **not** the `>16 bytes` reason I had recorded. Only `agr198_make_five`
is declined for its size.

So aggregate-return work has **zero executable coverage outside all-integer,
non-array, non-union shapes**, and I misattributed the reason in a commit
message. Fixing the extractor may be worth more than fixing the remaining
classes, because it converts a batch of `structural` cells into real verdicts
that would then say whether those classes are broken at all.

## Entry 83 — the extractor was worth more than the classes, and it settled a misattribution

Entry 82 ended with a guess: that fixing `extract_dwarf_signatures_path` might
be worth more than implementing the missing return classes, because it converts
`structural` cells into real verdicts. That guess was measured, and it held.

The extractor dropped any aggregate containing a float member, any array member,
and every union. Its stated reason — that the SysV eightbyte classifier puts an
all-float aggregate in SSE registers, so supporting one would mean guessing an
ABI the module cannot state — **describes a step that does not exist.** Nothing
in `src/debug/dwarf_signatures.rs` ever classified an eightbyte. libffi does
that, from the layout the descriptor already carries. `union {int64_t; double;}`
and `struct {int32_t v[2];}` were verified to return by value correctly through
`ctypes` before the descriptor was written at all.

Fixture 197 went from **6 signatures to 11**, and **70 cells left `structural`**
for a real verdict: 58 to `fail`, 8 to `pass`, 2 to `incomparable` (i386
`bv195_make_mixed`, correctly refused — 12 bytes there against 16 on the host
reference). Zero `pass -> fail` anywhere, across `@o0`, `@o2`, `@returns`,
`@aggregates` and the i386/armv7/aarch64 arch lanes.

Fifty-eight new `fail` verdicts is the point of the exercise. They were always
failing; the harness simply had no way to say so.

### The misattribution, now resolved

Entry 82 recorded that `bv195_make_big` was declined for size. It was declined
for its **array member**. The two reasons shared one detail string, so they were
indistinguishable in the output — which is exactly how a wrong reason survives
in a commit message. The string is now split, `"aggregate return of 32 bytes —
past the register cutoff"` against `"layout not describable from DWARF"`, and
`bv195_make_big` is now described (32 bytes, `int64_t[4]`) and declined for size
after all. It arrived at the same verdict by a different road, which is not the
same thing as having been right.

### The blocker that was real, and not the one that was stopping us

The stated reason for not implementing `HomogeneousFloat`, `SplitBanks` and
`SsePair` was that a synthesised struct tag cannot survive DecBench's snippet
slicing — and that is true, with the code to prove it: `split_c_functions` cuts
each snippet at the signature line and discards everything above, so a sliced
signature would name an undeclared tag, and C makes returning an incomplete type
an error.

But it was never a blocker for the lanes that prove soundness.
`tools/diff_decompile.py` builds the **whole** emitted unit into a shared object
and `dlopen`s it; above-signature emission already happens there today. And even
for DecBench it is dissolvable without a contract change, since C permits the
definition in the declaration specifiers:

```c
struct __glaurung_hfa_2d { double __m0; double __m1; } hfa197_make_pair2d(int a) { … }
```

which compiles clean under `-std=c11 -Wall -Wextra` on both `x86_64` and
`aarch64-linux-gnu`.

**The real blocker is representational.** `Stmt::Return { value: Option<Expr> }`
carries one expression and `Expr` has no aggregate-literal variant. `IntegerPair`
escaped because a double-word integer *is* a scalar: `(u128)lo | ((u128)hi << 64)`
is an ordinary expression that dead-store elimination and `verify_before_render`
already understand. The other three classes put bytes in two different *banks*,
so they need `return (TAG){ lo, hi };` with both operands visible to DSE or the
high half is deleted before it can be printed. Adding an `Expr` variant touches
56 files. The bit-pun shortcut does not work either: the reaching value of
`xmm1`/`d1` is float-typed in the AST, so widening it converts the number
instead of the bits.

That last sentence turned out to be the thread worth pulling — see Entry 85.

## Entry 84 — a five-line file blanked a typed dependency, and I had the diagnosis backwards

I recorded that the native extension had **no** type stubs, so `ty` reported
1,487 false attribute errors. It had stubs. That was the problem.

```
git show HEAD:python/pytest/__init__.pyi   | wc -l  →     5
git show HEAD:python/glaurung/__init__.pyi | wc -l  → 1,532
```

The five-line file was committed 2025-09-03 and sat on the first-party search
path, where **a `.pyi` shadows the module it describes**. It blanked the whole of
a fully typed pytest 9.1.1: **417 diagnostics** from one file nobody had opened
in a year. The 1,532-line hand-written stub of the extension had drifted far
enough to account for roughly 1,400 more — reporting real functions as missing
while silently vouching for signatures nobody had checked in months. It denied
`glaurung.debug` exists.

**A stale stub is strictly worse than no stub**, because it makes the checker
confidently wrong rather than merely blind. `ty` went **2,004 → 386**.

Both are deleted. `tools/gen_native_stub.py` introspects the *built* `.so` and
emits eleven files under `python/glaurung/_native/` plus six alias stubs.
Everything is typed `Any`, deliberately: PyO3 exposes `__text_signature__` —
names, arity, defaults — and no type information at all. `Any` keeps the stub
**sound**. It catches a call with the wrong arity or a misspelled keyword, and it
never invents a constraint the Rust does not impose.

`python/tests/test_native_stub_current.py` is what stops the replacement going
the same way, and its most interesting test is `test_the_comparison_is_not_vacuous`:
a stub regenerated from a stale `.so` matches a stale extension and passes while
both are wrong, so the test skips loudly when `build_guard` says the `.so`
predates its Rust. That is the same trap `tools/build_guard.py` exists to close
for fixture verdicts, reappearing one layer up.

I mutation-tested the guard rather than trusting it. One invented symbol appended
to `_native/ir.pyi`:

```
FAILED test_every_stub_matches_the_built_module
  ir.pyi: 33 lines on disk vs 32 generated
```

and green again on restore. It fails on drift, which is the only property that
matters.

### Three live defects fell out of making the checker usable

All three are hidden behind a bare `except`, and none would ever have surfaced as
a test failure.

1. `llm/agents/iterative.py:275` calls `kb.add_node(id=…, type=…, properties=…)`
   against `def add_node(self, node: Node)`. Guaranteed `TypeError`, swallowed at
   line 141 — so **every low-confidence refinement iteration dies at its feedback
   step and records the crash as a "failed attempt."** The loop looks like it ran.
2. `symbol_address_map` is called on a module that does not export it, at five
   sites, each inside `except Exception: pairs = []`. Measured: it is reachable
   from neither `glaurung` nor `glaurung.symbols`. It has been silently returning
   nothing.
3. Fifty-nine names in `triage.py:395-500` are referenced inside a
   `try/except AttributeError: pass`. None exists, so the block dies on its first
   line and `__all__` never gains any of them.

The pattern is one sentence long: **a bare `except` turned a hard failure into
silence, and the type checker was the only thing that could see it — which it
could not do while a five-line file was shadowing pytest.**

## Entry 85 — a ratchet you are routinely told to reset

Auditing my own commit found that `fd0b6455` raised `rustc:O0` undefined-read
violations from **7,525 to 7,535**, and nothing said a word.

```
git show 9dfd8457:tests/decompiler_fixtures/defuse_baseline.json → 7525
git show fd0b6455:tests/decompiler_fixtures/defuse_baseline.json → 7535
git rev-list 9dfd8457..fd0b6455                                  → one commit
```

A per-cell diff of every tracked cell between the two: **0 added, 0 removed, 0
changed.** All ten regressions are in functions the manifest makes no
per-function claim about — invisible to every per-cell assertion, visible only in
one aggregate integer.

`test_decompiler_defuse_census.py:115` is a real ceiling and would have caught
it. It did not, because I regenerated the baseline, which rewrote the ceiling to
the new and worse number.

The structural problem is not that I ran the generator. It is that the ratchet's
*other* half, `test_improvements_require_a_baseline_refresh`, **instructs** you
to run it, and adding any fixture requires refreshing all four baselines — and
`tools/gen_defuse_baseline.py` has no guard whatsoever. `grep -n
"recorded\|existing\|ceiling\|--allow"` matches nothing but `raise SystemExit(main())`.

**A ratchet that the documented workflow resets with an unguarded command is not
a ratchet. It is a record of the last time someone ran it.** This is the same
failure the fitness ratchet had, in a different file, four days later.

The fix is to make the generator refuse an upward move without an explicit
reason recorded in the file, while leaving downward moves and new-fixture cells
frictionless. The ten regressions themselves have names by now — they are real
rendering defects bought for the 24 execution cells that commit turned green,
and until this audit nobody had looked at them.

## Entry 86 — seven mnemonics lifted, and the two defects that were not on the list

`SILENT_REGISTER_WRITERS` went **35 mnemonics / 1,372 occurrences to 28 / 1,130**
— `tzcnt` (130), `bts` (82), `popcnt` (14), `movlhps` (6), `btr` (6), `btc` (2),
`rcr` (2, count-1 only), plus `movhlps` as the mirror of `movlhps`. The flag
writes are spelled as ordinary `Op::Bin { dst: VReg::Flag(..) }` rather than
multi-output intrinsics, so `value_number.rs:515`'s `outs.len() <= 1` guard is
never approached; the two intrinsics (`x86.ctz.*`, `x86.popcnt.*`) are strictly
one output.

Two of my premises were measured and overturned.

**"These live in `samples/` library code, not necessarily in the fixture
corpus."** Wrong, in our favour. Compiling all ~200 fixture sources at O0 and O2
under gcc and clang and grepping the disassembly found existing lanes for six of
them. `144_inline_asm:builtin_bit_intrinsics` compiles `__builtin_ctz` to `tzcnt`
with **no** `-mbmi` — `rep bsf` decodes as `bsf` on pre-BMI parts, so the
compiler emits it freely — including a memory-source form (`tzcnt -0x4(%rbp),%eax`)
absent from the sample census entirely. That lane was failing. It passes now, at
both gcc:O0 and gcc:O2.

**"`bsr` is about 2 occurrences."** It is 4, and all four are 16-bit `bsr si,cx`.
It stays unlifted, but the *reason in the code* is wrong and should not be
trusted by whoever picks it up: `bit_scan_ops` claims 16-bit would need an
`x86.clz.16` answering 16 too high, when `bsr16(x) = 31 - clz32(zext16(x))` is
exact with today's renderer. The real blocker is a bit-preserving partial view on
both source and destination, needing `read_view_ops` and `partial_write_ops`.

### The two defects that were not on the list

**`1 << n` was undefined for every n at or above 32.** `bts` lifted to
`dst | (1 << n)`, and `1` renders as a C `int`, so x86's 64-bit shift became a
32-bit one. Compiling the recovered text against the original disagreed for
*every* index from 32 up; at 63 it returned `0xffffffff80000000` where the
machine returns `0x8000000000000000`. This is a **general renderer defect** —
anything producing `(uint64_t)1 << n` suffered it — and it needed two fixes, not
one: the lifter widens the mask before shifting, and `const_fold.rs` had to stop
collapsing that widening cast back off, because C takes a shift's type from its
promoted left operand. The guard had to be ordered before the `is_exact_boolean`
arm, which accepts the constants 0 and 1 and was re-collapsing it.

Verified here directly, on `48 0f ab c8` (`bts rax, rcx`):

```
zext -> %t202  src=const 1  from=8 to=64
bin  -> %t202  shl  lhs=%t202  rhs=%t200
bin  -> rax    or   lhs=rax    rhs=%t202
```

The mask is widened *before* the shift.

**The `bt` family was poisoning ZF, which the architecture preserves.** Intel SDM
Vol. 2A, BT/BTS/BTR/BTC: CF receives the selected bit; OF, SF, AF and PF are
undefined; **ZF is unaffected.** `Op::Undef` is a real definition, so poisoning ZF
destroyed a live comparison that a preceding `cmp` produced and a following `je`
still read. The same lift confirms the fix — CF is written by an ordinary `Bin`,
and the undef list is `%of %sf %pf %af` with **no `%zf`**:

```
undef -> %of  "x86 BT/BTS/BTR/BTC define CF and leave OF/SF/PF/AF
               architecturally undefined; ZF is unaffected"
```

Neither defect was in the brief. Both came out of compiling the recovered C
beside the original and running them over all 64 bit indices, five payloads and
2^20 pseudorandom 32-bit values — which is the whole argument for differential
testing over inspection. A reviewer reading `dst | (1 << n)` sees correct C.

### And the ceiling that only pytest can see

`packed.rs` crossed 1,000 LOC when `movlhps`/`movhlps` landed (963 -> 1,042) and
failed `test_every_large_product_module_has_a_documented_review` — a **pytest**,
invisible to `cargo test`, and the second time this session that a Rust change
was gated by a Python test. It was split rather than review-listed, because the
test says to and because a 1,042-line "SSE integer and float lowering" file is
not one owner: `lift_x86/packed_halves.rs` (253) owns the six "move one 64-bit
half" mnemonics and `packed.rs` is 811.

With this family cleared, the census has a different shape: `syscall` (310),
`movsb` (242), `aesenc` (222), `movsq` (134). **The string moves are now the
largest tractable entry, and they were on nobody's list.** They write `rdi`,
`rsi` and memory — and `rcx` under `rep` — so a loop built on `rep movsq` leaves
both pointers holding their pre-loop values in the recovered C.

## Entry 87 — a bare `except` is a defect-hiding machine, and three were hiding behind one

Making the type checker usable (Entry 84) turned up three live failures, none of
which could ever have failed a test, all three for the same reason.

`llm/agents/iterative.py:275` called `kb.add_node(id=…, type=…, properties=…)`
against `def add_node(self, node: Node)`. Driving the real path with a real
`KnowledgeBase`:

```
RAISED: TypeError KnowledgeBase.add_node() got an unexpected keyword argument 'id'
kb node count: 0
```

Line 141 is `except Exception as e: state.failed_attempts.append(str(e))`, so
**every low-confidence refinement iteration died at its feedback step and
recorded the crash as a "failed attempt."** The loop looked like it ran. The same
defect sat at a second site I had not found, `iterative_refinement.py:546`, under
`except Exception: pass  # Soft fail on feedback injection`.

`symbol_address_map` was reachable from neither `glaurung` nor
`glaurung.symbols` — `src/lib.rs:89` registers it on the root `_native` module,
and the `symbols` submodule is a separate `PyModule::new` that never sees it.
Seven call sites, three different spellings, four of them broken, every one
inside `except Exception: pairs = []`. On `hello-gcc-O0`, ground truth 125 pairs:

```
map_symbol_addresses                     0 -> 125 symbols
xref_db.import_data_symbols_from_binary  0 -> 125 labels
```

And fixing it un-masked a second bug it would otherwise have caused:
`import_data_symbols_from_binary` is the only entry point in that module that
never calls `_ensure_schema`, and it got away with it because the
`AttributeError` returned 0 before reaching any SQL. Working lookup plus a fresh
KB gives `sqlite3.OperationalError: no such table: function_names`. **A silent
no-op was concealing a crash, and repairing the silence is what exposed it.**

Fifty-nine names in `triage.py` were referenced inside
`try: … except AttributeError: pass`. **Fifty-two have no Rust definition in any
commit** — `git log --all -S ElfHeaderFlags -- src/` returns zero. They were
never removed; they were never written. The other seven exist and are registered
on no Python module.

Three defects, one sentence: **a bare `except` turned a hard failure into
silence, and the type checker was the only thing that could see it.**

## Entry 88 — the ratchet, and what it was hiding

Entry 85 recorded that `fd0b6455` raised `rustc:O0` from 7,525 to 7,535 with
nothing said. Two corrections came out of chasing it.

**It is +16, not +10.** `rustc:O2` moved 4,451 -> 4,457 as well, and I had looked
at one lane and stopped.

**And it is not sixteen defects. It is ONE defect, TWICE, in ONE function,
replicated across eight statically-linked copies of the Rust standard library.**
`std::backtrace_rs::symbolize::gimli::resolve` goes 168 -> 170 in every lane that
emits it — five at O0, three at O2. 5×2 = +10, 3×2 = +6. A second function shows
up in a naive diff and nets zero: only a temporary's name moved, `var19` ->
`var21`, because the new lifting emits more temporaries.

The old render was right and the new one is wrong:

```c
// before -- an EXTRACT from the enclosing slot the machine actually writes
local_798 = ((unsigned long)((unsigned int)(((unsigned long)(local_bb8) >> 8))) | …);
// after -- a slot of its own, with no writer anywhere
// glaurung-verify: local_bb7 is read but never defined
local_798 = ((unsigned long)((unsigned int)(local_bb7)) | …);
```

`local_bb8 >> 8` is exactly the bytes at `-0xbb7`. `grep -c bb7` is 0 on the old
render and 4 on the new, and `local_bb7` never appears on a left-hand side while
all its neighbours do.

**The trade is sound and I am not fixing it first.** Sixteen undefined reads in
one Rust std backtrace-symbolizer body that already had 168, is not a corpus
contract, and is in no execution differential — against 24 execution cells that
went `fail -> pass` on contracted functions. The gcc and clang lanes cost
*nothing*: a full 764-lane census reproduces all four committed totals exactly.
The entire price was paid in Rust std internals.

The obvious fix is a trap. "If the resolved slot is never written, fall back to
the extract form" needs to know whether a slot is written, and `SlotVal` records
name, sizes and four flags — nothing about writes. That is a new analysis pass
over store destinations, inside the code that just bought the 24 cells,
validated only by an aggregate integer this whole exercise proves unreliable
per-defect. A fixture producing a misaligned sub-word view over a wider spill
comes first.

The generator now refuses to raise a ceiling without a recorded reason. I
mutation-tested it rather than trusting it, and got my own measurement wrong the
first time — reading `tail`'s exit status instead of the generator's and
reporting success for the refusing case. The generator's own status is 1.

## Entry 89 — the corpus cannot see the bug, because every lane is built with `-g`

Nine places decide whether to skip an exception region and they do not agree. One
disagreement is unsound: `repair.rs:175` tests landing-pad ownership against a
function's **walked** extent, while the FDE extent is used only as a stop bound.
GCC and Clang park the landing-pad trampoline after the epilogue and inside the
same FDE, so the test rejects exactly the bytes the pass exists to recover. It is
circular — code with no normal predecessor is rejected because normal flow did
not reach it.

On this repository's own `136_cpp_exception_unwinding.cpp` at `g++ -O2` with no
`-g`: three of five LSDA sites rejected, and the bytes `0x14d5..0x14e1`,
`0x153b..0x1544`, `0x1567..0x1573` belonged to **no function at all**. The
emitted pseudocode carried three `goto L_14d0;` and zero `L_14d0:` labels — C
that will not compile. On libstdc++, 3,248 LSDA sites: **2,415 rejected (74%)
before, 37 after**; landing pads attached 833 (26%) -> 3,204 (99%).

**And the corpus can never catch it.** `-O0` attaches 5/5. `-O2 -g` attaches 5/5,
because `apply_dwarf_overrides` hands the function the wide DWARF range. It fails
only on optimised builds *without* debug info — and `fixture_harness.py:253`
passes `-g` to every fixture compile, unconditionally.

That is the more important finding. An entire class of defect — anything whose
recovery depends on function extents when DWARF is absent — is structurally
invisible to `tests/decompiler_fixtures/`, which is exactly the configuration
real targets ship in. The cheapest useful answer is probably not a second `-g`
axis across 200 fixtures, but stripping one existing lane post-link and diffing
the recovered output against the `-g` version, because the *difference* is the
signal: for a correct decompiler, debug info should improve **naming**, never
**structure**.

The sibling finding was also real, and link-order dependent as claimed.
`merge_compiler_split_chunks` folded each child into its immediate parent, so for
`foo <- foo.part.0 <- foo.part.0.cold` the leaf could be merged into a fragment
the pass then deletes. Demonstrated with three real `gcc -O2` objects linked two
ways:

```
... mid.o leaf.o     foo 14 blocks, 2 ranges   <- cold fragment gone
... leaf.o mid.o     foo 17 blocks, 3 ranges
```

Same objects, same flags, only the link line differs; three basic blocks of
executing code lost. Not hypothetical either — `libwebsockets.a` carries
`lws_context_destroy`, `.part.0` and `.part.0.cold` simultaneously.

Neither fix moves a single corpus cell, in either direction. That is the correct
result and it is worth stating plainly: **a change that fixes a real defect and
moves no cell is evidence about the corpus, not about the change.**

## Entry 90 — three claims re-derived, and only one survived as written

Three roadmap claims went out to be re-measured rather than trusted. The
scoreboard is the point: **one real, one latent, one simply wrong.**

**Real, and every instance in the sample was broken.** RIP-relative addressing
does not exist in 32-bit x86, and `classify_pe_thunk_head` took no architecture
at all — it resolved `FF 25 disp32` as `entry + 6 + disp` unconditionally, while
`classify_function_shapes` admits `BArch::X86` explicitly. Measured against the
import table parsed out of the file itself:

```
thunk entry=0x004071e0  head=ff25fcc14000
  computed=0x8133e2  (NOT-AN-IAT-SLOT)
  operand =0x40c1fc  (msvcrt.dll!wcslen)
thunks whose computed target is NOT a real IAT slot: 35 / 35
```

Not one PE32 import thunk in that binary had a usable target.

**Latent, not live.** `lower_conds.rs` really did carry two functions named
`expr_reads_memory`, the nested one shadowing the shared one and disagreeing on
three `Expr` variants, with two more walkers fail-open on `_`. But mismatches
attributable to any of it, across **1,128 images**: zero. `WideArithmetic`
reaches a `while`-header preamble 21 times, so the hole is structurally live —
five targeted C loops compiled 40 ways render byte-identically before and after.
Fixed as hygiene; the roadmap wording corrected from "can freeze a loop
condition" to "latent fail-open".

**Wrong.** `xmm_views.rs:121` demands exactly four lanes under a comment saying
"every lane the instruction wrote". Logging every call with `lanes_seen` in
`1..=3` — a strict superset of the disagreement — over the same 1,128 images:
**197 hits, every one `lanes_seen == 2` with all four lanes written**, and both
readings decline them. True disagreements: zero. The code was right; the comment
was the wrong half.

That is the second wrong *reason* in a comment found today, after `bit_scan_ops`
claimed 16-bit `bsr` would need an `x86.clz.16` answering 16 too high when
`31 - clz32(zext16(x))` is exact. **A comment that states a reason is a claim,
and it decays exactly like a number does.**

## Entry 91 — the fix that deletes forty switch arms

The fallthrough-only index bound really is applied to dispatch blocks with other
predecessors: `cfg.rs:1394` records it as an **edge** fact and `cfg.rs:1127` and
`:1475` apply it as a **block** fact with no predecessor check. Measured: 6
occurrences across 78 system ELFs, **0** across 1,107 fixture binaries.

All six are benign, and for a reason worth knowing — GCC tail-duplicates the
range check, so every extra predecessor carries the *identical* guard and reaches
the dispatch on the taken edge of a `jbe`, which we do not model at all.

Then the part that matters. Refusing `index_bounds` on multi-predecessor blocks
— the obvious fix, the one I would have written —

```
/usr/bin/3cpio 0x2f4cf   resolved 40 arms  ->  0, dispatch invalidated
```

**Forty real switch arms deleted.** `export_stable_bounds` deliberately strips
the last-`cmp` bound, so the `jbe` predecessors export nothing and the sound join
proves nothing; removing the unsound-looking shortcut removes the only fact
there was. The sound direction is the opposite one: model the taken edge so every
predecessor proves its own bound.

An agent measured that before proposing it, and reverted the experiment. That is
the whole value of the rule about measuring before believing a premise, including
one I supplied.

The same investigation retired a second claim: the trim path is **not**
`-O1`-only (8 `needs_bound_proof` dispatches, 4 at O1 and 4 at O2, 0 at O0) and
produces **zero trims at any level**, so the `-O1` axis I had considered would
have doubled corpus runtime for nothing. What actually creates coverage is
adjacency of jump tables in `.rodata`, which is now fixture 204 — landing
deliberately red, pinning a guarded switch that loses all seven arms because its
guard is a `cmp` against an indexed memory operand the tracker does not accept.

## Entry 92 — I recorded a wrong reason in a baseline, and it is retracted there

The def-use guard refused to raise `rustc:O0` from 7,535 to 7,560. I attributed
it to a stale fixture build cache, wrote that reason into
`defuse_baseline.json`, and moved on.

It cannot be true. `compile_fixture` and `_compile_rust_fixture` both recompile
**unconditionally** — neither has an `exists()` short-circuit — and
`defuse.jobs()` enumerates **declared lanes**, not files in `build/`. No cached
object can enter that census. An agent read the code and said so; I had not.

Worse, the 7,535 I compared against was **never measured on a fresh build**. I
read it from a run whose `.so` had been reverted for an A/B and not rebuilt
afterwards. `tools/build_guard.py` names that condition in one line
(`STALE: … is newer than the built extension`) and I had not run it.

The 17 six-day-old objects I measured in `build/` were real, and the cache key
genuinely omits its compiler flags — that is a defect, filed. It just is not
*this* defect. **A true observation next to a wrong conclusion is more
dangerous than a wrong observation**, because the evidence looks like support.

Three attempts to attribute it properly failed: reverting `cfg.rs` to
`965f8585^` no longer compiles against the current `entry_shape.rs` signature.
Rather than guess a fourth time, the reason recorded in the baseline is now an
explicit retraction naming what was ruled out by measurement (the DWARF and
float-store work contributes zero — byte-identical per-function output with
those patches stashed) and what remains a candidate.

Two rules came out of it, both now in `CLAUDE.md`: run `build_guard.py` before
every baseline regeneration, and rebuild in **both** directions of an A/B, not
just into the before-state.

## Entry 93 — the corpus cannot see stripped binaries, and it turns out it can

Entry 89 recorded that every fixture builds with `-g`, so an entire class of
defect is invisible. The cheapest fix looked like a second axis nobody would run.

That was wrong, and one measurement settles it:

```
original: 8 exported symbols (nm -D), 6 debug sections (readelf -S)
stripped: 8 exported symbols,         0 debug sections
ctypes.CDLL(stripped.so).f201_f32_slot_bits  ->  callable
```

`strip` removes `.symtab` and the DWARF and leaves **`.dynsym`** — and a shared
object's exported functions live in `.dynsym`. So the existing execution
differential works on a stripped object **unmodified**: same compile, strip the
output, `dlopen` and call exactly as now. No new harness mechanism.

And the right framing is a differential against the `-g` build of the same
source, which is stronger than a standalone verdict: **for a correct decompiler,
debug info should improve naming, never structure.** Any cell that passes with
`-g` and fails stripped is a real defect carrying its own control.

The landing-pad defect of Entry 89 — 74% of libstdc++'s LSDA sites rejected,
dangling `goto`s in the emitted C — was invisible to all 198 fixtures for exactly
this reason. It is the configuration real targets ship in, and it is where the
decompiler has to work hardest, because extents, signatures and types all come
from analysis rather than being handed over.
