# Open questions

> **Kind:** design · **Status:** proposed

Ideas that are not implemented, and measured negative results that stopped an
implementation. Each section ends with **the experiment that decides it**,
because the reason these are written down rather than done is that nobody has
run that experiment yet — and the expensive part of each of them is the
analysis, not the code.

Nothing here is scheduled. The scheduled work is
[`development/roadmap/`](../development/roadmap/README.md).

---

## Goto sinking: fewer gotos cost more GED

Goto density is the second-largest readability gap after declaration count.
Measured function-weighted over 93 ground-truth functions: Glaurung 8.63 gotos
per 100 lines, Ghidra 3.18, angr 1.99.

The structure of ours is unusually tractable. Over the 409 gotos in that
corpus, 316 (77.3%) target a label reached by exactly one goto, and 102 of
those also have no fallthrough into the label — but **zero** are at the same
nesting level as their goto. Every fully sinkable case has its `goto` nested
deeper than the label: the label sits at function level and the jump comes from
inside an `if`. A same-level inliner therefore fires on nothing at all, which
rules out the obvious cheap fix and is why the pass that was written *sank* the
block down to the jump rather than inlining it upward.

Sinking is sound under a stated precondition. When exactly one `goto` targets a
label and nothing falls into it, that goto is the block's only predecessor: the
block executes exactly when the goto is taken and never otherwise, so moving it
to the goto site preserves the execution set wherever that site is nested,
including inside a loop. The one thing that must not be lost is the block's own
exit — a block that ended by falling through into the *next* label depended on
its position, so only a block ending in an unconditional transfer may move.
Appending a synthetic `goto next` would widen applicability and manufacture a
jump the reader did not have, which is the opposite of the goal.

**The pass worked and still lost.** It removed 11% of emitted gotos. Wiring it
in cost `statemachine:gcc:O0` a GED of 10 → 35 plus five `byte_match` cells,
and `src/ir/goto_sink.rs` was deleted (verified absent). Fewer gotos is not the
same as a control-flow graph closer to the source's: moving a block to its jump
site changes where that block sits in the region tree, which is exactly what
GED measures.

The open question is not "should we sink gotos". It is: **what readability
metric does this project optimize alongside GED, and is goto density in it at a
weight that can beat a 25-point GED regression on one function?**

**The experiment that decides it.** Define the readability objective first —
the census in `tools/` already produces goto, break, switch and declaration
counts per lane, so the missing piece is a stated weighting, not more
measurement. Then re-derive the pass against that objective on the same corpus
and check whether the `statemachine:gcc:O0` trade is one the objective accepts.
Do not reintroduce sinking before the objective exists; the analysis above is
the expensive part and it stays true, but the implementation was ~330 lines of
routine tree surgery and can be rewritten in a day.

---

## Two loop passes that never fire: retire, or repoint

`src/ir/loop_form.rs` holds three structural recovery passes, all still present
and all instrumented (`recover_sentinel_search_loops` at :237,
`recover_guarded_do_whiles` at :250, `recover_owned_pretested_do_while` at
:320; six `pass_stats` call sites across the three).

Measured on 2026-08-15 over every one of the 754 built objects in
`tests/decompiler_fixtures/build/`, decompiling every `T` symbol in each, with
`GLAURUNG_PASS_STATS=1` driving `decompile_many` (**not** the CLI, which does
not reach these passes at all):

| pass | attempts | fires |
| ---- | -------: | ----: |
| `recover_owned_pretested_do_while` | 21,035 | **21** |
| `recover_guarded_do_whiles` | 5,580 | **0** |
| `recover_sentinel_search_loops` | 2,790 | **0** |

That measurement has not been re-run since; the numbers are cited with their
date rather than restated as current. An earlier table in the same document
claimed different counts and turned out never to have been produced by any run
at all — the instrument did not exist at the commit that quoted it — which is
the origin of this project's rule about writing the command next to the number.

`recover_owned_pretested_do_while` is live, just rare. The other two fire zero
times, and that is worse than dead code rather than equivalent to it: they are
reachable and are offered thousands of bodies, so nothing in the corpus has
ever exercised their **output**. The first time either fires it will be on a
binary nobody has checked, and a structural rewrite that fires and produces
wrong C is worse than one that never fires.

For `recover_sentinel_search_loops` the gap is understood rather than guessed.
The input it was written for exists as a fixture — `192_pointer_chased_list`,
whose `l192_find_key` is the probe verbatim — and it still does not fire. The
matcher wants `While { cond: match_continue }` with a 2–3 statement body and a
bare `Expr::Const` sentinel; the pipeline emits `while (1) { …; if (match)
break; …; }` with four statements and a **cast** zero. That is a different
shape, not one clause too strict, so widening the matcher amounts to writing a
new pass against the shape the pipeline actually produces.

The pass is also demonstrably correct on the input it was designed for: probed
directly, it fires under `clang -O1` and `-O2` on a parameter-passed linked
list advanced by a pointer chase through a struct field, and not at all under
`-O0` or any gcc level. Three near-misses — a pointer *increment*, an index
walk with a bound test, and a linked walk over a `static` pool built in the
same function — all fire zero times, because the matcher requires the advance
to be a LOAD.

**The experiment that decides it.** Re-run the fire counts at HEAD first; they
are two years of pipeline changes old in decompiler terms and the passes may
have moved without anyone noticing. Then, for each of the two zero-fire passes,
choose deliberately: either rewrite the matcher against the shape the pipeline
emits today and add the fixture that proves it fires, or delete the pass and
record that its shape is handled elsewhere. Do not leave a third option open —
a reachable, unverified structural rewrite is a liability that costs nothing
until the day it costs everything. Giving `recover_sentinel_search_loops`
standing coverage needs a harness feature, not another `.c` file: the
differential builds arguments from caller-owned integer buffers, so a
`struct node *` parameter whose `next` fields are real addresses into that
buffer is not something `tools/diff_decompile.py` can synthesize today.

---

## Stack-bias affine index

The idea survives; the branch that held it does not (`agent/stack-bias` @
`4ac7657`, retired in the 2026-08-13 branch audit). Verified absent from `src/`
today: `affine_of`, `affine_of_expr`, `collect_affine_index_defs`.

The analysis records, per register, a definition of the form
`root * scale + bias`, guarded two ways — and the guards are the interesting
part:

* both ends must be version-stable, so a later redefinition cannot invalidate
  the fact and the fold names the same value at every use; and
* a self-rooted definition is rejected outright, because it is a
  read-modify-write of a non-SSA register and folding it would silently shift
  every later use.

The payoff is stated by the branch's own test name: *a constant bias folded
into the index still reaches the displacement*. Today a constant bias folded
into an array index stops the index being matched against the frame
displacement, so the slot is not recognized as the local it is.

The reason it was not merged is not the idea. The branch also introduced
`StackAddressDefs`, a context struct threaded through eleven signatures across
`stack_locals.rs`, in the same region master had rewritten independently.
Line-wise, master held 339 lines the branch did not against 170 the branch held
that master did not, so taking it wholesale would have lost about twice what it
gained — and a textual reconciliation of that region is the precise hazard the
[master-integration record](../history/design/repo-operations/master-integration-2026-08-12.md)
documents: it compiles, silently keeps one side's fix, drops the other's, and
the merged behaviour matches neither side's recorded baseline, so no baseline
catches it.

**The experiment that decides it.** Do not resurrect the branch. Port only the
affine analysis — `affine_of`, `affine_of_expr`, `collect_affine_index_defs`,
`is_version_stable` and the two guards — against master's current model,
leaving `StackAddressDefs` behind; bring its unit test, which is written
against the helpers rather than the threading. Then add the fixture that makes
step one falsifiable: an array indexed with a constant bias (`a[i + 3]`) in a
frame whose slot recognition currently fails. Without that fixture there is no
answer to "did this improve recovery?", which is exactly the state the branch
died in. Only afterwards ask whether anything still wants `StackAddressDefs`;
master's model may already carry those facts by another route.

---

## The four-workstream redesign behind the DecBench defect reproductions

[`history/design/campaigns/decbench-defect-reproductions-2026-08-27.md`](../history/design/campaigns/decbench-defect-reproductions-2026-08-27.md)
§7 proposes four redesigns rather than four patches, and says of itself that
"if adopted, it belongs in the roadmap". It was never adopted, and the roadmap
it named has since been archived, so it is recorded here as an open proposal.
The document is pinned to Glaurung `5e168798`; its diagnoses were checked
against code at the time and its line citations have drifted since.

* **P1 — dispatch-site-first indirect branch resolution.** Two systems today
  cooperate badly: a blind whole-binary `.rodata` scan with no end marker by
  construction, and a per-site abstract interpreter that can only answer
  register-operand sites. Memory operands, 8-byte strides, ARM A32, PE and
  AArch64 fall between them silently. The proposal inverts the dependency —
  the dispatch *site* becomes the unit of analysis, the table scan becomes a
  seeding hint, `EntryEncoding` becomes an enum instead of an assumption, and
  every refusal is counted rather than absorbed.
* **P2 — an unmodelled instruction must declare its register footprint.**
  Chasing mnemonics one at a time does not close the hole, because the
  fallback sites keep re-opening it. The proposal makes "I don't know what
  this computes" expressible without also saying "and it writes nothing": the
  refusal sites already hold the decoded instruction and know the destination,
  and the template already exists in the packed-string lifter's single-output
  intrinsics.
* **P3 — grow the structuring algebra before touching the predicates.** Two
  local fixes have been tried and reverted, and the reason is in the type
  definitions: `Region::{While,DoWhile}` carry one `exit` and
  `Region::{IfThen,IfThenElse}` carry one `join`, so split ownership cannot be
  spelled and every predicate patch is a trade between shapes. The proposal is
  ordered: compute a loop forest once in `Cfg::from`, replace the
  `stop_at: Option<usize>` boundary with a region context, make the join
  oracle loop-relative, split the overloaded `visited` set — and only then
  decide whether the LLIR structurer becomes total and the AST passes become
  renderers, or the split is deliberate and gets a written rule.
* **P4 — the gates that would have caught all of this.** Every defect above was
  mis-described in our own docs while every gate stayed green. Both the fixture
  ratchet and the def-use census are perfect-count-shaped and cannot see *how
  wrong when wrong*. The proposal adds a distance gate (median and mean GED
  over a fixed corpus), an indirect-dispatch census per architecture and
  encoding, an empty-body guard, and a prototype-stability check against DWARF.

**The experiment that decides it.** P4 first, and independently of the other
three: it is cheap, it needs no redesign, and until a distance gate exists
neither P1 nor P3 can be judged, because both are expected to move *mean*
rather than perfect count. P1 and P2 each have a falsifiable first step that
does not commit to the redesign — a fixture per encoding for P1 (there is
currently none for the non-PIC absolute form and none for ARM A32), and the
destination-naming change at a single refusal site for P2. P3 should not be
started until P4's distance gate is reporting, and note that removing the
`switch_ladder` compensation before P3 lands would regress a gcc `-O0` lane
that passes today.

---

## Knowledge-base schema migration

`python/glaurung/llm/kb/persistent.py` pins `SCHEMA_VERSION = "1"` and fails
closed on anything else: opening a database whose `schema_version` differs
raises `RuntimeError(… "migrations are not yet implemented")` at
`persistent.py:215`. Failing closed is the right default. It is not a
migration story, and the KB is now 35 `CREATE TABLE` statements across nine
modules — `xref_db.py` alone has 13 — holding the analyst-entered data
(function names, comments, types, prototypes, stack variables) that the whole
`.glaurung` project format exists to keep.

[`history/refactoring-portfolio-2026-08/06-knowledge-base-boundaries.md`](../history/refactoring-portfolio-2026-08/06-knowledge-base-boundaries.md)
proposed the target: a `kb/schema/` owning versioned migrations and integrity
checks, SQL confined to storage modules, provenance surviving round trips, and
unknown future versions failing with a clear error rather than being opened
optimistically. None of it is built. The open question is narrower than the
proposal, and it is a product question: **is a `.glaurung` file expected to
outlive the build that wrote it?** If yes, bumping `SCHEMA_VERSION` is a
breaking change to user data and needs migrations before the next bump, not
after. If no, that should be stated in the project-file documentation, because
today a user's only signal is a `RuntimeError` after the fact.

**The experiment that decides it.** Write the migration test before the
migration: check in a `.glaurung` file produced by a released build, add a test
that opens it with the current code, and see what happens. That single fixture
converts the question from a design debate into a red test, and it is the one
piece of evidence the proposal above never had — its own stop condition says
migration testing against a freshly created database proves nothing.

---

## `FunctionFacts` and `CallFactStore`

Still literally unimplemented: `rg 'FunctionFacts|CallFactStore' src/` returns
nothing. It was the most duplicated open item in the archived roadmap —
counted three times across two epics and a phase — and it has exactly one
design, kept live beside this file at
[`function-facts-and-call-facts.md`](function-facts-and-call-facts.md). Read
its §6 before starting: four measurements there show the existing `CallGraph`
cannot be the foundation (it fails its own `validate()`, its roots are absent
from `nodes`, 41% of its nodes are synthetic `sub_<hex>`, and it is keyed by
name), which reverses the first step the roadmap used to recommend. The
experiment that decides that one is stated in the design itself.
