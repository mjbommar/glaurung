# Runtime instruction trace

> **Kind:** architecture · **Status:** maintained

## Persistence boundary

`analyze_and_persist_instruction_trace` reloads the exact capsule and payloads
from a `.glaurung` project, verifies the executable identity, and stores the
canonical report. Each inferred `OperationOccurrence` is split into a singular
runtime/static identity and one or more content-addressed evidence views. This
preserves differing relation-specific input projections without duplicating the
static LLIR operation or attaching observed values to it.

`glaurung.runtime_capture.capture_instruction_trace_child` single-steps one
owned Linux x86-64 child between cooperative begin/end checkpoints. It has no
PID-attach surface. The checkpoints select a bounded acquisition interval; they
do not describe the expected operation, address, object, or result.

The provider records at most 4,096 instruction transitions and compares a
fixed 4,096-byte stack window after each transition. Instruction addresses and
ordering remain public capsule metadata. Changed-byte records and the
pre-instruction register set for a changing step share one versioned sensitive
external payload. A separate, single hash-bound register-trace payload retains
pre-instruction registers for every public step, keyed by and validated against
its public sequence and address. This permits a call with no immediate stack
change to become an occurrence without publishing register values or creating
one payload per step. The before/after windows and final bounded stack page are
also sensitive external payloads,
each bound by ID, length, and SHA-256. Exhausting the time or step budget fails
the capture rather than publishing a complete trace. The capsule explicitly
marks broader process state as partial.

`glaurung-runtime-instruction-trace-report-v1` validates each changed-byte
payload and resolves the instruction address through the exact runtime mapping
and `ProgramImage`. Its original `relations` stream remains restricted to
changed stack bytes. A separate `executed_stores` stream covers every stepped
instruction that resolves to exactly one LLIR `store`, including stores with no
stack delta. It evaluates the LLIR memory operand with observed
pre-instruction registers and emits a canonical occurrence with the resulting
address and width. For changed-stack relations, those values must still equal
the observed changed interval. Missing or tampered payloads, wrong images,
ambiguous mappings, and zero or multiple LLIR stores remain unknown.

The report also has a `control_transfers` stream. For each stepped direct
`jump` or `cond_jump` that resolves to one exact LLIR operation, it keeps the
declared static target, the ptrace-observed successor PC, the successor's own
static resolution, and whether the observed edge was the target or conditional
fallthrough. These are occurrence-scoped edges; they do not delete unobserved
CFG edges or imply complete block coverage. Static condition slices retain
comparisons and width conversions when available. A separate
`condition_call_results` relation uses LLIR def-use plus the known Linux
x86-64 SysV result register to identify a unique reaching call result. An
intervening result-register definition or another call breaks that relation.

The first dangerous-sink control gate is the paired GCC `-O0` PIE execution of
`danger_ioctl_input`. The provider obtains the exact `argv[1]` address from
Linux `arg_start`/`arg_end`, records that observation at trace begin, and the
analyzer independently verifies the bytes in one hash-bound captured page.
This avoids confusing the argument with equal bytes in an environment value.
The input is joined to the exact `strcmp` occurrence and its observed return
value. Exact observed control edges
then retain the `strcmp`-dependent branch inside `rs_bad`, the caller's
predicate return, and the request-selection branch in `main`. The selected
stack store and the ioctl request load share one static frame-address
expression, while occurrence registers show either zero or `0xdeadbeef`
written and supplied to the exact ioctl call. One typed
`InputToCallArgumentRelation` owns this full join. A shifted input address,
missing page payload, or impossible observed successor makes the relation
unknown. Branchless and alternate-compiler lowering shapes require distinct
propagation variants.

GCC `-O2` adds the first branchless propagation path. The optimizer keeps the
request in `rsi` and lowers the choice to a conditional move. The shared LLIR
represents that instruction as `Ite`; the static operation records its output
register, alternatives, used/defined registers, and the reaching `strcmp`
result. A `value_selections` occurrence records pre/post registers and the
selected output. The aggregate relation accepts this path only when the sink
uses the same ABI register, the observed value agrees, and every intervening
exactly resolved instruction leaves that register undefined. A changed
post-selection register makes the relation unknown. The eight GCC good/bad,
`-O0`/`-O2`, PIE/non-PIE cells pass.

Clang `-O0` adds a composed spill path rather than another invented branch.
Within `rs_bad`, occurrence-scoped taint starts at the observed `strcmp`
return register, follows exact LLIR def/use operations, records the concrete
one-byte stack write and same-address reload, and reaches the observed
predicate return. The caller's exact LLIR `Ite` then selects the request, an
exact store writes it to `main`'s frame, and the ioctl argument loads from the
same static address expression. `SpilledPredicateReturnConditionalMemory`
retains each link without putting the observed addresses or values into LLIR.
Changing only the spill's observed base register, while updating the payload
identity, removes the matching write/reload and makes the aggregate relation
unknown.

Clang `-O2` inlines the predicate and selects the sink register on two
observed control paths. The bad path executes an exact LLIR definition
`esi = 0xdeadbeef`; the good fallthrough executes the exact expression
`esi = esi ^ esi`. A `value_definitions` occurrence stream requires the
post-step register to agree with the immutable LLIR expression. The
`BranchSelectedRegister` propagation joins the `strcmp`-dependent edge to one
such definition and requires the register to remain undefined until ioctl.
A hash-consistent post-definition register mismatch makes both the definition
and aggregate relation unknown. All sixteen good/bad, GCC/Clang, `-O0`/`-O2`,
PIE/non-PIE cells now pass.

The trace-begin checkpoint also enumerates the owned child's descriptor table.
Only caller-allowlisted targets are retained; every other target stays
redacted, and procfs enumeration is explicitly marked raced. The semantic
projection can therefore join the exact ioctl occurrence and observed return
to an authorized descriptor identity even though tracing begins after
`open`. It emits `scenario_selected->ioctl` only from one inferred aggregate
relation. For the paired zero-request control, that same bounded evidence
supports only the specific negative `untrusted_ioctl_request = false`; it does
not turn the partial trace into global file-event completeness. Both semantic
oracles pass in all sixteen cells. Breaking either Clang propagation path with
a hash-consistent mutation removes the dataflow fact and fails the bad oracle.

The first exact byte-propagation gate is a separate
`danger_command_argument` family. Its trace begins after command selection and
observes one real `argv[1][0]` byte being loaded and written into the command
buffer that is later printed, then loaded from that buffer and written to a
second destination. `input_value_flows` keeps the input source and
runtime location separate from immutable LLIR value semantics. A successful
relation records the exact `(source_id, source_offset, byte_len)` span, the
statically resolved source-memory address, the exact load occurrence that read
that memory version, and the observed destination write. A separate
`executed_loads` stream evaluates each uniquely lifted LLIR load with its own
pre-instruction registers and creates its own canonical occurrence. The flow
requires exactly one matching load after the memory version was created and
before its consuming store. The destination bytes must equal the hash-verified
source bytes; matching addresses or static def-use alone do not count.

This gate also exposed and corrected a static slicing error: an `eax`
definition was not treated as a definition of canonical `rax` storage, so the
stored-value slice incorrectly retained an older pointer value. Register
storage equivalence now comes from the shared x86 register-view model. Clang's
partial-register read/modify/write form is accepted only when the preserved
side contributes zero to the written byte. All eight GCC/Clang, `-O0`/`-O2`,
PIE/non-PIE lanes pass. Shifting the declared input location while retaining a
valid capsule makes the relation unknown. The analyzer maintains an ordered
runtime provenance map: a store clears the overwritten range and creates its
next version only when the observed bytes equal the original source spans. A
hash-valid mismatch at the first write therefore removes the later flow too.
A hash-valid effective-address mutation on the second load preserves the first
flow edge but removes the second. This is a bounded one-byte, two-load,
two-store slice; it does not yet establish arbitrary memory provenance,
or unchanged-write handling.

The same complete instruction stream now produces `observed_blocks`. Each
inferred relation is one maximal sequence-contiguous run of exact instruction
starts that resolves to one exact image, function, native basic block, and raw
LLIR block. The relation retains both native and lifted block identities rather
than assuming their coordinates are interchangeable, and each step retains its
runtime PC, normalized static VA, exact static instruction extent, and LLIR
operation indices and kinds. Re-entering the same static block starts another
occurrence because a control transfer is not linear instruction continuity;
the capture/thread and first/last event sequences therefore participate in the
stable occurrence ID. An event-sequence gap, unresolved address, interior PC,
ambiguous function/block, lift failure, or instruction without resolved LLIR
operations ends the current occurrence and emits an explicit unknown relation.
Observed blocks do not add or remove static CFG edges, imply that unobserved
blocks did not execute, or claim complete path coverage. A capsule mutation
from an instruction start into its interior proves the fail-closed boundary in
the first command fixture lane.

Each exact main-image `observed_blocks` relation now receives its own
`replay_seeds` relation. It imports that occurrence's hash-verified
pre-instruction canonical x86-64
registers and architectural flag bits into `exec::Machine<Concrete>`. Memory is
not borrowed from the capsule's later final-page view. Instead, the adapter
starts with the latest preceding time-scoped runtime-object snapshot and
applies every intervening provider-complete stack delta in sequence, requiring
each recorded `before` interval to equal the reconstructed bytes. Only those
reconstructed ranges are initialized in the machine. The report retains source
and seeded hashes, reconstruction bounds, applied-change count, and read-back
verification counts. Because the generic execution memory returns synthetic
zero for unset cells, the runtime adapter explicitly marks every address
outside the seeded ranges unknown; bounded replay must enforce that coverage
before executing a load. Missing snapshot bytes, incomplete deltas, overlap,
register/PC disagreement, or unsupported target architecture withholds the
seed. All eight command build lanes pass, and removing only the initial stack
snapshot leaves observed blocks intact while making the seed unknown.

Each inferred seed now contains a `bounded_replay` of that exact observed
block. The adapter executes only the operation indices named by every observed
instruction step and stops before any load, store, call-stack transition, or
return-stack read outside seeded coverage. It compares the resulting control
transfer with the next observed instruction, registers written by the block,
and every seeded memory byte after applying the observed deltas. For x86-64 it
currently supplies only the runtime mechanics that raw LLIR deliberately omits
for opcode-proven direct near calls (`e8`) and near returns (`c3`): pushing the
runtime fallthrough address, reading the concrete return address, and updating
`rsp`. Other call/return forms remain unknown.

Static-image addresses produced by LLIR are never silently rebased. If a
register or eight-byte memory value differs only because the observed value
resolves through the capsule's exact module mapping to the replayed static VA,
the report retains an `address_normalized_*` comparison with both values and
the mapping ID. All other unequal values are divergences. Registers explicitly
poisoned by `Op::Undef` are excluded from equality comparison and listed in
`uncompared_registers` with the LLIR reason; the executor's stale backing bit is
not evidence. The GCC/Clang, O0/O2, PIE/non-PIE command matrix passes this
bounded terminal-state comparison. The blocks are seeded and replayed
independently from captured state; this is not yet chained path replay or
process emulation.

Each replay seed also owns an optional `first_divergence`; successful replay
leaves it absent. A divergence has a typed kind (`unsupported_operation`,
`missing_environment`, control-flow, register, or memory mismatch), a state
component and replayed/observed values where applicable, and the exact event
sequence, static instruction VA, LLIR block, operation index, and operation
kind responsible when one exists. The real GCC/O0 command negative control
changes only the hash-verified successor `rsp` and obtains a `register_mismatch`
attributed to the terminal return operation. A dedicated real-binary lane
compiles the same corpus sample with user-mode `smsw` immediately after trace
begin. That exact later block lifts to a memory-touching intrinsic, replay stops
before inventing its effect, and `first_divergence` reports
`unsupported_operation` with the intrinsic's event, instruction, block, and
operation identity. Out-of-coverage paths use the distinct
`missing_environment` kind.

`solver_query_candidates` is the first counterfactual-selection layer over the
trace. For each exactly located invocation source it starts byte-granular
provenance at that occurrence's concrete runtime addresses, then interprets
the exact raw-LLIR operations associated with each observed instruction.
Register definitions, concrete loads, and concrete stores transfer sets of
source offsets. A candidate is emitted only when an exact `cond_jump` reads a
tainted predicate register and the same event has one exactly related observed
edge. It records the source-byte spans, predicate registers, event and thread,
immutable LLIR operation, and the edge that actually occurred.

This propagation is deliberately fail-closed. Missing pre-step registers and
unresolved semantics clear live provenance; calls and opaque intrinsics are
register barriers. The selector neither annotates the static CFG nor claims
that an unselected branch is input-independent. It also does not invoke a
solver. The dedicated GCC/O0 branch lane proves a one-byte `argv[1][0]`
selection, and the ordinary GCC/Clang, O0/O2, PIE/non-PIE command lanes prove
that copying an input byte without branching on it yields no candidate.

With the `symbolic` feature, each selected candidate also attempts one bounded
counterfactual over the same interpreter used for concrete replay. A fresh
`exec::Machine<Symbolic>` receives the captured registers and captured memory
at the first exactly resolved instruction in the selected function. Only the
candidate's public input-byte spans become fresh symbols. Exact LLIR operations
replay the observed prefix; prior symbolic branch conditions retain their
observed polarity, and the selected condition receives the opposite polarity.
The existing solver seam returns either a typed satisfiable model, an
unsatisfiable result, or a typed unknown. A satisfying result contains only
byte mutations, not a second copy of private or unaffected input data.

The authoritative native-Axeyum gate starts with `cad`, obtains the one-byte
patch `0x62`, and
runs the real binary again with `bad`. That second capture resolves to the same
LLIR conditional operation and traverses the predicted opposite static edge.
This is deliberately bounded: calls, opaque or unresolved operations after the
seed point, missing memory, symbolic addresses, and private input prevent a
witness. A build without `symbolic` preserves the same report schema and emits
`unknown/no_solver` rather than silently omitting the attempted relation.
The same real-binary lane has fail-closed variants: withholding the initial
stack payload yields `missing_environment`; executing `smsw` before the branch
yields `unsupported_semantics`; and performing a safe concrete load through
an input-derived address yields `symbolic_pointer`. Solver wall timeout and
deterministic work exhaustion map to distinct `solver_timeout` and
`solver_resource_limit` outcomes.

Indirect control targets remain runtime relations rather than static CFG
updates. For an instruction with exactly one immutable LLIR `IndirectJump` or
indirect `Call`, the analyzer joins the post-step PC to an exact target address
under capture, process, thread, and sequence scope. It retains both the raw
runtime successor and static source/target identities and creates one ordinary
`OperationOccurrence`. An unmapped or ambiguous successor leaves the target
and occurrence unknown. Trace absence never removes a static candidate, and an
observed target is never presented as the complete target set. The first real
fixture uses a volatile function pointer and persists its indirect-call
occurrence without modifying `ProgramImage`, `ProgramEnvironment`, or an LLIR
operation. The eight-cell GCC/Clang, `-O0`/`-O2`, PIE/non-PIE gate proves that
call relation, its fail-closed unmapped-target control, and project persistence
without requiring incidental compiler-specific indirect jumps.

The report separately measures address-correlation coverage for the exact
analyzed image. It identifies module mappings by content identity, not path,
then counts every traced PC within those mappings. Exact resolutions and full
typed failure records are retained. If the provided image does not match any
captured module, the whole coverage relation is unknown; zero selected steps
can never masquerade as complete coverage. The default eight-cell matrix has
equal observed and exact counts with empty failure lists in every cell.

Two sink-bearing lanes validate that this machinery changes consequences, not
only control flow. In `memory_index_write`, native Axeyum proves that changing
`cad` to `bad` reaches the neighboring path; the new capture follows the
predicted edge and the existing stack-write relation
places the four-byte write in `canary`. In `danger_command_argument`, the same
one-byte mutation follows the predicted edge and an ordinary execution of the
same binary emits a semicolon-bearing command marker and `metachar 1`. The
test harness performs materialization and validation today; the report does
not yet claim an automatically owned validation relation.
The corresponding `crash_null_write` lane begins with a safe traced branch,
materializes the solver's `bad` neighbour, captures its real core, and obtains
the existing `null_write` crash classification at an exact LLIR store. This
closes the crash-side evidence gap but deliberately leaves production-owned
validation and bounded-UNSAT reporting as later Objective 10 work.

An optional bounded heap timeline captures one stable `[heap]` mapping before
the trace, at its end checkpoint, and at a subsequent cooperative checkpoint.
The mapping must remain identical and no larger than 1 MiB. An executed store
may then relate its bounded static address slice and observed register value to
one DWARF pointer local. A distinct object-transition relation verifies the
stored constant against the immediate post-store bytes and retains later bytes
without writing either value into LLIR or DWARF.

For the bounded heap gates, `heap_interposer` instead records one complete
main-module allocation/free chain, with zero or one interposed write, in the
same launched child. Acquisition reads the exact allocator object while the
child is stopped at trace begin, trace end, and post-trace. Those provider
events, instruction steps, and snapshots are normalized onto one capsule thread
and one ordered sequence. Provider sequence
and OS-thread identities remain explicit fields. Stream byte high-water marks
observed while the child is stopped at trace begin, trace end, post-trace, and
termination prove where each provider record belongs in the shared sequence.
Malformed, incomplete, multi-object, cross-thread, or wrong-phase chains fail
capture. This mode is mutually exclusive with the generic heap-mapping timeline
so one address range cannot silently acquire overlapping runtime-object
identities.
`heap_snapshot_multiple_objects.c` exercises the multi-object rejection with a
real child and ensures selection does not discard an extra main-module object.
`heap_snapshot_no_object.c` similarly proves that a summary-only provider
stream is not accepted as a complete combined capture.
`heap_snapshot_worker_object.c` proves that a valid chain from another OS
thread is not attached to the traced main-thread occurrence stream.
`heap_snapshot_wrong_phase.c` proves that provider-local ordering is
insufficient when the observed checkpoint boundaries disagree.

The first real gate is `memory_struct_field_overwrite` built with GCC and Clang
at `-O0`, in both PIE and non-PIE forms. In all eight good/bad cells the trace
observes one direct one-byte write
to `0xaa` and resolves it to the exact LLIR store. The existing stack relation,
without a trace-specific variable model, recovers the same `main` frame and
DWARF `struct box b`: the good run changes `data[7]` from `00` to `aa`; the bad
run changes the first `canary` byte from `44` to `aa`.

The static operation additionally carries a bounded LLIR backward slice of its
address expression. This is immutable static semantics, not captured values.
The stack relation evaluates that slice with the occurrence's observed
registers and sparse memory, then joins expression subvalues to the independent
DWARF layout. It therefore retains two different truths in the bad run: the
concrete destination is contained by `canary`, while the address expression is
based on `data` with element index eight and exceeds that eight-byte field by
one byte. The good run derives index seven and remains within `data`. Both runs
now satisfy their complete semantic oracles without the analyzer reading them.

The report includes its observed instruction count, count of steps with stack
changes, fixed-stack-window scope, and partial broader-runtime-state status.
This matters in optimized builds: Clang `-O2` represents this fixture's logical
canary result in a register and the bounded stack trace observes no matching
`00/44 -> aa` write. That absence is scoped to the compared window; it is not
reported as proof that no semantic consequence occurred.

A second eight-cell `-O0` gate uses `memory_index_write` to prevent the first
case from defining the algorithm accidentally. Its four-byte LLIR store and
DWARF `uint32_t a[4]` layout derive `a[3]` as in bounds and `a[4]` as crossing
four bytes into `canary`. The semantic projection retains all four changed
bytes and reports the bound in elements rather than confusing byte length with
array cardinality. Both scenarios satisfy their complete independent oracles
across GCC/Clang and PIE/non-PIE.

A third eight-cell gate, `memory_off_by_one`, covers multiple writes in one
trace interval. Snapshot-derived field changes remain reportable when the
responsible `memset` instruction is outside the exact main-image operation
relation; missing attribution no longer discards observed bytes. Conclusions
shared by several changing steps are deduplicated. The direct boundary write
retains its statically sliced stored value, so a zero byte into a `char[]` is
reported as `terminator:index=8:declared_length=8`, while the concrete changed
destination remains `tag`. Good and bad semantic oracles pass across the same
four `-O0` build configurations.

A fourth eight-cell `-O0` gate, `memory_memcpy_overflow`, crosses from scalar
stores to a semantic call. The analyzer independently requires one exact LLIR
`call`, retains its immutable direct target, and resolves `memcpy` through the
ELF PLT relocation. CET `.plt.sec` and legacy `.plt` layouts share the same
static import index. Observed SysV `rdi`, `rsi`, and `rdx` values become
occurrence inputs and a concrete runtime-object write effect. The existing
DWARF relation identifies `box.dst` and reports the bad 12-byte call as
crossing the eight-byte field into `canary`. Missing or inconsistent register
payloads remain unknown. The provider still single-steps through the external
implementation; stepping over proven calls remains a performance requirement.

`memory_memmove_overflow` is the second eight-cell semantic-call gate. Its
fixture routes the operation through a no-inline pointer-parameter wrapper so
the compiler must preserve overlap-capable `memmove` semantics instead of
legally rewriting a visibly non-overlapping call to `memcpy`. The same call
model, occurrence inputs, runtime-object effect, DWARF relation, and semantic
projection satisfy both independent oracles. This establishes reuse across two
real imported operations while making compiler transformation part of the test
evidence rather than trusting the source spelling.

`memory_strcpy_overflow` adds a third imported-operation family across eight
cells. Because `strcpy` has no explicit length argument, the occurrence derives
its bounded source byte count, including the terminator, from the hash-verified
pre-call stack snapshot. Missing source payloads and an absent terminator remain
unknown. The logical write extent stays separate from endpoint byte changes:
copying `"ABC\0"` into zeroed storage writes four bytes but changes only the
first three. This gate corrected the good-case oracle to describe the actual
changed interval rather than conflating touched and changed bytes.

`memory_strcat_overflow` adds a fourth eight-cell family. Two bounded scans of
the same hash-verified pre-call snapshot recover the source extent and the
existing destination extent. The resulting occurrence distinguishes append
bytes, actual write start at the old terminator, and final string extent. Its
logical effect can therefore begin inside `box.dst` while the final extent
proves that the result crosses into `canary`. Missing snapshot evidence fails
closed. Individual writes inside the library remain visible but do not acquire
an invented semantic operation name when no static occurrence is proved.

The imported functions are implemented through typed semantic-call
contracts rather than one branch per fixture. Fixed-length copy,
NUL-terminated copy, and NUL-terminated append produce distinct derived-extent
types before runtime-object resolution and occurrence construction. Adding a
new callee therefore requires selecting or defining its semantic shape instead
of reinterpreting the generic `byte_len` field.

`memory_sprintf_overflow` adds a fifth eight-cell family and a fourth contract
shape. The analyzer accepts only an exact captured `%s` format, reads the
variadic source from the distinct SysV argument register, and derives the
logical output extent from captured source bytes. Other formats remain
unsupported. This preserves format identity, source identity, touched output,
and changed endpoint bytes as separate evidence. The gate also corrected a
good-case oracle that had counted an unchanged terminating zero as changed.

`memory_overlapping_copy` adds an eight-cell semantic-precondition gate. The
same observed source and destination ranges overlap in both scenarios. The
exact `memmove` occurrence is valid and remains a clean control; the exact
`memcpy` occurrence produces `overlap_violation` with object-relative source
and destination intervals. Its bare `char b[16]` also exercises object-level
snapshot changes without inventing a field identity.

`memory_underallocation` adds the first non-stack executed-store gate. Across
GCC/Clang `-O0`, PIE/non-PIE, and good/bad scenarios, the direct four-byte
initialization resolves to one LLIR store of `0x24681357`. Its static address
slice loads the DWARF pointer local `canary`; the occurrence supplies the
concrete heap address. Three same-execution snapshots prove zero bytes before
the store, `57136824` immediately after it, and either the same bytes in the
good run or `aaaaaaaa` after the later `memset` in the bad run. The semantic
projection therefore produces the paired canary unchanged/changed assertions.
The allocation call, direct store, interposed `memset`, and free share one
capture identity while retaining distinct occurrence identities. In the good
case no single provider write explains the aggregate allocation diff, so the
whole-object responsible-write relation correctly remains unknown even though
the individual `memset` occurrence is resolved. In the bad case that `memset`
covers every changed byte and may be attributed. Stripping DWARF preserves the
occurrence, address, and byte history but removes the source-pointer conclusion.

`memory_heap_canary_overwrite` is the second non-stack executed-store gate and
does not use an interposed write. Its indexed one-byte store resolves through a
compound LLIR address slice: recursive bounded traversal finds both frame-slot
loads, but only the unique DWARF pointer-typed local `p` is accepted as the
source pointer. Across the same eight build lanes, checkpoint snapshots prove
the exact object-relative write at offset seven or eight and its `00 -> ff` or
`78 -> ff` transition. The provider-neutral object diff correctly leaves the
responsible write unknown because no bounded provider write event exists; the
separate executed-store occurrence retains attribution. Source-field and
eight-byte logical-prefix claims remain separate: an occurrence-time
reconstruction of `p`, the observed `calloc(1, n + 8)` occurrence, its bounded
`Load(n) + 8` LLIR input slice, and the DWARF scalar `n` now prove an eight-byte
logical prefix without shrinking the observed 16-byte allocator object. The
offset-seven store stays within that prefix; the offset-eight store crosses it
by one byte while remaining inside the object. A separate allocation-tail
relation reconstructs all fixed-width DWARF pointer locals at that occurrence
and accepts the unique pointer whose value equals the source-derived tail
start. In this fixture that independently identifies `canary` at object offset
eight; its four-byte pointee history comes from the same three hash-verified
snapshots. The semantic projection therefore emits both good-run facts (`p[7]`
changed and `canary` unchanged) and both bad-run facts (indexed bounds
violation and the one-byte `canary` change) in all eight lanes. The independent
`memory_interval_semantic_result` producer exposes those facts without loading
the corpus oracle; mutating its produced index makes the evaluator fail.
Removing the trace-end object payload
preserves the operation, pointer, and prefix relation but makes only the byte
transition unknown; removing the initial stack payload or stripping DWARF
preserves the occurrence and object bytes but removes the pointer and dependent
prefix and tail conclusions. Unsupported pointee spellings, non-frame storage,
or multiple locals with the same tail pointer remain unknown.

The provider is still not a general trace facility: additional threads,
per-step non-stack byte comparison, signals other than its checkpoints,
hardware tracing, optimized lanes, and other architectures remain open.
