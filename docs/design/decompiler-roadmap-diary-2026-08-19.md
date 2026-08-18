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
