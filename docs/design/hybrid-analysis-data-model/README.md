# Hybrid analysis data model

> **Kind:** design · **Status:** proposed

This folder defines how Glaurung's static binary, decompiler, execution, and
runtime-analysis models should meet. It is a design proposal, not a description
of shipped runtime-analysis support.

The immediate evidence is the 60-program runtime corpus and capture harness:

- [`tests/runtime_samples`](../../../tests/runtime_samples/README.md) contains
  15 normal, 15 deterministic-crash, 15 silent-corruption, and 15 dangerous-
  behaviour programs, each with good and bad scenarios;
- [`tools/runtime_sample_harness.py`](../../../tools/runtime_sample_harness.py)
  builds, runs, stops, and captures process metadata for those programs; and
- the [runtime-analysis roadmap](../../development/roadmap/runtime-analysis.md)
  defines the intended capsule, acquisition, correlation, crash, corruption,
  event, persistence, and product work.

The provider-neutral metadata contract has now landed as
[`glaurung-process-capsule-v1`](../../architecture/runtime-process-capsule.md).
The product capture surface emits that model for an owned stopped child and
imports Linux x86-64 ELF cores into it. Secure payload-bundle import, sparse
runtime reads, crash reconstruction, runtime object snapshots, and the first
object-change analyzer have also landed. Exact runtime-to-static relations do
not mutate either model: they resolve exact images, mappings, PIE/non-PIE
addresses, unwind-backed functions, targeted CFG blocks, decoded instructions,
and source-addressed LLIR operations. Bounded IOCTL and input-read traces now
produce execution-specific `OperationOccurrence` records for exact LLIR call
operations; selected read occurrences retain the capsule input source they
introduced. The first same-execution read checkpoint also retains the concrete
bytes under a mapping-scoped runtime snapshot while keeping that runtime object
separate from static variables and types. A relation report can now join that
evidence to an inferred runtime frame and authoritative DWARF object/field
contract, while the static contract and runtime occurrence retain separate
identities. A bounded interposed heap-write case also relates an observed
runtime write to its exact static callsite and one occurrence-scoped
runtime-object effect. A first bounded single-step provider also observes a
direct stack-byte change, resolves its exact LLIR store occurrence, and reuses
the DWARF stack-object relation to identify the changed field. Its static
operation retains a bounded address-expression slice while the occurrence
retains external observed registers; their typed relation proves `data[7]`
in-bounds and `data[8]` crossing into the separately reported `canary` field
across GCC/Clang `-O0` PIE and non-PIE configurations. Optimized-out storage
does not become an invented runtime object: trace absence stays scoped to the
captured stack window and broader runtime state remains partial. The same
relation handles a second, four-byte array-index fixture: static
element width, observed index, DWARF field extent, and concrete destination
remain separate inputs to the resulting bounds fact.
The third representative shape retains whole-field snapshot changes even when
an interposed/library write lacks an exact static operation, while a separate
direct store uses immutable stored-value semantics to identify an off-by-one
null terminator. Runtime evidence is neither discarded for want of attribution
nor copied back into the static operation.

The next representative shape now spans a complete semantic library call:
`memory_memcpy_overflow` resolves a direct LLIR call through relocation-backed
ELF import identity, attaches observed SysV arguments to one occurrence, and
joins its logical write effect to the same DWARF object and independent byte
snapshots. Static call targets remain immutable; register values and concrete
effects remain execution-scoped.
The identical relation now covers a preserved `memmove` call. A compiler that
rewrites it to `memcpy` changes the static fact; runtime analysis does not use
the fixture's source name to override the operation actually present in the
binary.
Implicit and compound string calls now exercise the same boundary. `strcpy`
derives its touched extent from captured source bytes, while `strcat` retains
the old destination length, append extent, actual write start, and final string
extent as distinct occurrence facts. Endpoint byte differences remain a
separate observation in both cases.
The next call shape, `sprintf`, proves an exact captured `%s` format before
interpreting the variadic source argument. Static import identity does not
authorize a generic formatting model, and unsupported formats remain unknown.
A temporal heap case now preserves an allocation instance beyond its observed
destruction solely as identity and history. A later interposed `memset` remains
an occurrence-scoped write to an ended object; it does not revive the object or
mutate a static variable. A bounded static slice of the first candidate ABI
register input, the exact `memset` contract, the observed destination, and a
unique DWARF pointer slot now form a separate relation proving that source
local `p` points to the allocation for that occurrence. Broad absence of post-destruction writes remains unknown
because `memset` interception is not whole-machine write coverage.
A scalar arithmetic case now crosses the same boundary without turning a
decompiler variable into mutable runtime state. Static LLIR retains a bounded
width-reducing expression, DWARF retains the source-variable contracts, and
instruction occurrences retain registers and concrete values. A separate
typed relation resolves those ingredients to the executed `requested ->
narrowed` conversion and a subsequent exact `memset` field effect. GCC and
Clang may use different static stack-coordinate expressions; equality is
established only after both resolve to the same occurrence-scoped runtime
address.
The under-allocation case makes the object boundary equally explicit. A
runtime `calloc` object retains its full observed extent; a bounded static
`Load(n) + constant` argument slice and DWARF scalar contract define a separate
prefix relation. A later write may cross that source-derived prefix while
remaining inside the allocator object. Neither boundary overwrites the other,
and missing DWARF removes only the prefix conclusion. A distinct transition
joins the exact write occurrence to immediately bracketing object snapshots,
keeping logical-prefix and reserved-tail byte history separate. It does not
call the tail a source `canary` from those facts alone. A separate bounded trace
now supplies the required executed direct-store occurrence: immutable LLIR
address/value slices, observed registers, one DWARF pointer local, and three
same-execution heap snapshots produce the canary changed/unchanged facts. The
allocator, direct store, later interposed `memset`, snapshots, and deallocation
now share one capture identity and ordered event stream in the representative
case. Each static operation still has a separate occurrence identity. The
aggregate object diff remains unattributed when no single bounded write covers
all changed bytes; it is not rewritten as one synthetic operation.
The same capture shape now covers `memory_heap_canary_overwrite` without an
interposed write: exact allocator-object bytes at the three stopped checkpoints
join an indexed LLIR store to the DWARF pointer local `p` across the eight
GCC/Clang PIE/non-PIE lanes. Occurrence-time stack reconstruction proves that
`p` equals the allocator-object start; a separate allocation occurrence,
bounded `Load(n) + 8` slice, and DWARF scalar contract preserve an eight-byte
logical prefix inside the 16-byte object. The good store ends at that boundary;
the bad store crosses it by one byte. The semantic layer projects those as a
within-prefix changed interval and a prefix-bounds violation respectively.
A separate relation reconstructs the occurrence-time values of fixed-width
DWARF pointer locals and identifies the unique pointer equal to the derived
tail start. That relation, rather than allocator containment or the variable
name, proves the source local `canary` and its four-byte snapshot history. Both
good and bad semantic oracles now match in all eight lanes. Missing object and
stack payloads and stripped-DWARF controls weaken only the byte transition,
source identity, and dependent prefix/tail claims respectively.

General semantic
traces, downstream input propagation, broad OS-event analysis, and broad
corruption classification remain unimplemented. Existing static relations do
not by themselves assert that an operation completed during the captured
execution.

The instruction trace now makes the corresponding control boundary explicit.
An immutable LLIR `cond_jump` supplies its declared target and bounded
condition semantics; an occurrence relation supplies the actually observed
successor and call-result dependency. The static CFG is not pruned, and the
concrete edge is not written back into `FunctionIR`. In the first
`danger_ioctl_input` good/bad lane this preserves the chain from the input comparison
through two call-result-dependent branches to the selected request store and
ioctl load. A separate typed relation owns the aggregate source-to-sink join;
it references, rather than mutates, each static operation and runtime
occurrence.

The same relation now has a distinct branchless variant for GCC `-O2`.
Immutable LLIR `Ite` semantics describe the alternatives and output register;
runtime evidence records which value occurred and proves register continuity
to the sink. No concrete value is written onto the static `Ite`, and no
conditional edge is invented. GCC's eight default cells pass.

Clang `-O0` demonstrates why this boundary must remain compositional. Its
predicate result travels through an observed stack spill/reload before the
caller uses an LLIR `Ite`, and the selected request is then spilled again
before the sink. A typed occurrence flow joins exact LLIR def/use and address
expressions to concrete register and memory identities. Neither spill is
added to the static data model as an execution fact.

Clang `-O2` supplies the complementary inlined case. The static operation owns
the selected register definition and its expression; a `value_definitions`
occurrence owns the pre/post registers and the value agreement. The aggregate
relation joins that definition to the observed comparison edge and proves the
register survives to the sink. A runtime mismatch does not rewrite or
invalidate the static expression; it withholds the occurrence relation. All
sixteen default matrix cells now pass across four explicit propagation shapes.

Semantic projection remains another relation layer. It joins the typed trace
relation to an allowlisted trace-begin descriptor identity and exact ioctl
return; it does not copy descriptor paths into LLIR or infer provenance from a
request value. This closes the paired good/bad semantic assertions across the
same sixteen cells. A damaged runtime flow removes the semantic dataflow fact
without changing any static operation.

The OS-context path follows the same split. A normalized `chmod` occurrence
retains its process/thread sequence, authorized or redacted path identity,
requested mode, and kernel result. The `world_writable` conclusion is derived
from that runtime occurrence; it is not stored on a static call operation or
inferred from the fixture's output label.

Likewise, a successful process-creation occurrence and a later parent-side wait
may be joined by their capture-scoped OS PID to derive created/reaped counts.
That relation does not turn the child PID into a static program identity or
manufacture a child `ProcessSnapshot` whose registers and mappings were never
captured.

## Documents

| document | purpose |
|---|---|
| [Current state](current-state.md) | Evidence-bounded 2026-09-17 checkpoint: implemented vertical slices, intentional unknowns, remaining objective gaps, and validation boundary |
| [Ghidra comparison](ghidra-comparison.md) | Compare Glaurung's current architecture, data structures, and algorithms with Ghidra, and identify the decompiler consolidation worth carrying forward |
| [Reuse boundaries](reuse-boundaries.md) | Define which concepts binary and runtime analysis share, which records remain separate, and how evidence crosses the boundary |
| [Objective ladder](objective-ladder.md) | Order the programme from authoritative fixtures through exact identity, semantic crash/corruption analysis, temporal replay, bounded counterfactuals, portability, and blinded real-world closure |

## Governing decision

Glaurung should share a **semantic kernel**, not a universal mutable program
object:

```text
                    shared semantic kernel
             target, storage, values, types, operations,
                identities, provenance, completeness
                              │
             ┌────────────────┴────────────────┐
             │                                 │
       static world                       runtime world
  immutable file image              captured process state
  discovered CFG                    processes and threads
  possible behaviour                mappings and sparse pages
  inferred variables/types          observed events over time
             │                                 │
             └──────── evidence joins ─────────┘
                              │
                    findings and explanations
```

The decompiler must not become the owner of processes, threads, mappings,
events, allocation lifetimes, or capture completeness. Runtime analysis must
not create parallel definitions of targets, instructions, values, types,
symbols, operations, findings, or provenance.

The join is explicit and evidence-bearing. Static facts remain static; observed
facts remain observations of a particular execution; replay and symbolic facts
name their models and bounds. Correlation never erases those distinctions.

The shared kernel now reaches the decompiler's shipped variable inventory as
well as runtime relations. DWARF variables and types use exact-image debug-info
origins. Recovered ABI parameters and uniquely located frame locals use the
canonical static function plus ABI position or frame coordinate and recovery
profile. These are immutable static-variable nodes: a runtime frame or object
may be related to one, but never becomes one. Rendered names do not participate
in identity and ambiguous storage receives no identity. Structurally recovered
parameter hints now mint graph-owned type nodes keyed by semantic shape, target
width, exact image, and recovery profile; C spelling is only an attribute, and
text-only stack-local types still mint nothing. The remaining consolidation is
live-range-aware high-variable identity, broader structural recovered types,
semantic-value bindings, and AST/token navigation—not storage of runtime values
in decompiler objects.

The first implemented crash join demonstrates this rule. An observed null fault
address and proven read/write direction can be related to one exactly resolved
LLIR load/store width to produce `read:null:width=N` or
`write:null:width=N`. The width remains a property of the immutable static
operation, while the address and direction remain claims about one execution.
The derived semantic fact owns neither input and is unavailable when the
relation is missing or ambiguous.

The first selected-read join applies the same rule to input provenance. Stable
input bytes remain execution-scoped source identities; an exact LLIR read-call
occurrence retains the concrete destination effect; and DWARF retains static
object/field layout. A separate relation maps source subranges onto the runtime
field intervals they wrote without copying input state into the static
variable or claiming downstream propagation.

The first downstream byte-flow join preserves the same boundary. For
`danger_command_argument`, runtime evidence owns the concrete `argv[1]` range,
source bytes, destination addresses, and observed writes. LLIR owns the
immutable load/mask/store expressions and architecture register-storage
projections. The relation alone says that source byte zero reached the command
buffer and then a second occurrence through an ordered runtime memory version.
It does not taint the static variable, mutate LLIR, or turn one execution's byte value
into a decompiler fact. A runtime/LLIR disagreement withholds the relation and
is treated as evidence to repair semantics, not permission to override them.
The source loads and destination stores retain distinct canonical operation
occurrences and sequences; a backward expression slice is not itself temporal
evidence.

The first observed-block join applies the boundary at the next larger unit.
Native CFG and LLIR blocks remain immutable. A separate execution occurrence
owns each sequence-contiguous run of exact traced instructions and retains its
capture, process, thread, sequence range, and both block identities. Repeated
visits do not collide, and missing trace evidence does not become a static
reachability claim.

The first concrete replay seed continues that separation. It copies
occurrence-time registers and a temporally reconstructed, hash-verified subset
of runtime memory into a fresh `exec::Machine`; neither static nor captured
objects become execution-engine containers. Seed coverage remains an explicit
relation, so the machine's implementation default for unset cells cannot turn
missing runtime evidence into observed zeroes.

The first bounded replay now executes that occurrence's exact raw-LLIR
operations and compares its known terminal-state projection with the next
observed state. Runtime-only call/return stack mechanics live in the adapter,
not in `ProgramImage` or the captured capsule. PIE values are equal only through
an explicit mapping-backed static/runtime address relation retained in the
result; they are never normalized in place. Poisoned LLIR outputs remain named
unknowns rather than becoming stale concrete values. The representative
command case passes GCC/Clang, O0/O2, and PIE/non-PIE lanes. Exact observed
blocks are independently seeded; they are not yet chained into arbitrary
function or process replay.
Replay failures now have a typed first-divergence relation rather than only a
free-text mismatch: it keeps occurrence position and immutable LLIR operation
identity alongside distinct replayed and observed state. The real successor
register mutation gate proves the mismatch path. A dedicated real-binary
`smsw` lane proves the separate unsupported-operation path and retains the
opaque intrinsic's exact static identity without inventing its runtime effect.

The first solver-query selector preserves this split as well. It propagates
byte-granular input provenance through exact LLIR operations only along one
observed instruction stream, then creates a separate candidate relation for
an exact conditional-jump occurrence and its exact observed edge. The relation
owns its source spans, predicate registers, process/thread/event coordinates,
and branch direction; LLIR and the static CFG remain unchanged. Conservative
barriers withhold candidates rather than turning missing runtime semantics
into independence. A real guarded command fixture selects exactly the branch
that consumes `argv[1][0]`, while the normal eight-lane command matrix produces
no candidates. This is prioritisation for a future solver query, not symbolic
execution or a generated neighbouring input.

The next bounded step now does generate one neighbouring input without
crossing that boundary. A fresh symbolic machine reuses the shared LLIR
interpreter, constrains the already observed prefix, negates the selected
branch occurrence, and asks the existing solver seam for a model over only the
attributed public bytes. The guarded command gate produces `c` to `b`; a new
real capture validates the predicted opposite edge at the same static
operation. The model and prediction remain counterfactual facts, while the
validation remains a separate execution. Builds without a solver and attempts
that cross missing, symbolic-pointer, unsupported, or privacy boundaries retain
typed unknown outcomes rather than changing LLIR or fabricating a witness.
The same bounded mechanism now closes W8 on consequence-bearing cases: one
neighboring input changes an indexed stack write into a DWARF-confirmed canary
write, and another changes the command marker into a semicolon-bearing sink.
Both reruns retain the predicted LLIR branch identity. The production
validator now owns this workflow: it verifies the original input identity,
materializes the bounded byte patch, launches the exact binary into a new
capture, and emits a separate validation relation. The crash lane takes a safe
`crash_null_write` trace to `bad`, then classifies the real core as a null write
at the predicted LLIR store. A two-branch command lane proves bounded UNSAT for
the later alternative while retaining the earlier observed branch constraint.
Its proposition records exact event and LLIR-operation identities plus path,
memory, input, and solver bounds. Solver-returned unknowns retain those same
bounds; failures before query construction explicitly say that no proposition
was constructed. Together these are the representative Objective 10 exit
evidence; Objective 11's cross-process and concurrent causality is next.

Persistence and export preserve the same separation. A redacted runtime
evidence packet inventories capture identity, completeness, content hashes,
report identities, claim kinds, and explicit omissions without embedding raw
runtime state. Only the explicit `include_sensitive` policy embeds the exact
capsule, typed report documents, and payload bytes. Neither policy serializes
runtime values into `ProgramImage`, LLIR, SSA, or decompiler variables, and the
executable remains a separately controlled hash-identified artifact.

## Immediate consequence

The next runtime milestone should not add process fields to `ProgramImage` or
teach decompiler AST nodes about PIDs. It should specify the smallest shared
identity and evidence contracts required by the first five cases named in the
[runtime roadmap](../../development/roadmap/runtime-analysis.md):

1. `crash_null_write`;
2. `crash_bad_function_pointer`;
3. `memory_struct_field_overwrite`;
4. `danger_rw_to_rx`; and
5. `normal_open_file`.

Those cases jointly force address correlation, terminal state, thread state,
sparse memory, object identity, mapping transitions, OS events, provenance,
and negative evidence without first attempting whole-OS modelling.
