# Static and runtime data-model reuse boundaries

> **Kind:** design · **Status:** proposed

This document decides how Glaurung's decompiler model should and should not be
reused for live processes, core dumps, process capsules, and traces.

## Decision

Reuse definitions of machine meaning, stable identity, types, symbols,
operations, provenance, completeness, and findings. Do not reuse static object
containers as runtime state, decompiler inference as observation, or a single
address namespace for unrelated processes and moments.

The separation is:

```text
StaticProgram                 RuntimeExecution
  ProgramImage                 ProcessCapsule
  ProgramSession               Process / Thread
  discovered functions         Mapping / ModuleInstance
  FunctionIR                   Snapshot / EventStream
  possible CFG edges           observed events
          │                         │
          └── CorrelationGraph ─────┘
                    │
             EvidenceFact<T>
```

`CorrelationGraph` is not a second program database. It contains typed,
provenance-bearing relations between immutable identities in the two domains.

## Reuse matrix

| concept | reuse? | rule |
|---|---|---|
| target architecture and ABI vocabulary | yes | One target model defines register files, widths, endianness, calling conventions, and instruction semantics |
| instruction decoder and lifter | yes, with byte-source identity | Decode captured bytes through the same decoder, but record whether bytes came from the file, a runtime page, or fallback |
| LLIR operation semantics | yes | Concrete replay, symbolic execution, static analysis, and runtime explanation should agree on operation meaning |
| architecture storage identity | yes | A register observation and LLIR operand may join only through a target-defined storage projection |
| `ProgramImage` | no | It remains one immutable file/object image; a process is not an image and runtime pages must not mutate it |
| `ProgramSession` | as coordinator, not container inheritance | It may reference correlated runtime sessions and facts, but does not own live mutable process state |
| static `Address` alone | no | Runtime locations require process, mapping, module instance, time/snapshot, and resolution status |
| symbols and types | yes as identities/facts | Runtime evidence may corroborate or refine them, but every fact retains source, scope, confidence, and lifetime |
| static CFG | yes as a candidate graph | Observed edges annotate it; absence from a trace never deletes a possible edge |
| decompiler SSA value | conditionally | Join only at a proven instruction occurrence and execution context; one SSA value can have different concrete values across executions and loop iterations |
| high variable | conditionally | It describes recovered source-level identity, not a runtime allocation or one concrete storage instance |
| memory object vocabulary | yes | Stack, global, heap, mapping, TLS, and unknown are shared kinds; identity and lifetime remain runtime-specific where applicable |
| MemorySSA | no direct reuse across time | Static MemorySSA describes program order and alias reasoning; runtime memory versions require event/snapshot order and thread context |
| region tree or AST | presentation only | Runtime annotations may attach through semantic origins; runtime facts must not be stored in syntax nodes |
| `MemoryView` concept | yes, current trait no | A common bounded-read abstraction is useful, but runtime reads need source, coverage, permissions, snapshot, and structured omission information |
| findings and provenance | yes | One finding schema consumes typed evidence from any domain without flattening claim kinds |
| completeness and budgets | yes | Static truncation, capture omission, event loss, and solver bounds use a shared vocabulary with domain-specific reasons |

## Shared semantic kernel

The shared kernel contains definitions that are independent of whether a value
was inferred statically or observed at runtime.

### Target and storage

Define target storage without process state:

```text
StorageSpaceId     register, memory, constant, temporary, architecture-specific
StorageLocation    space + offset + width + optional lane/subpiece
StorageProjection  relation between aliases such as RAX, EAX, AX, AL
```

Runtime register sets and LLIR operands both map into this vocabulary. The
runtime record still carries thread and snapshot identity; the LLIR record
still carries value and operation identity.

### Semantic operations

Decoding and lifting should produce the same operation semantics regardless of
whether instruction bytes came from a file image or a captured executable
page. The byte origin is part of the evidence:

```text
CodeBytesOrigin =
  StaticImage(image_id, file_range)
  RuntimePage(snapshot_id, mapping_id, range)
  ProvenStaticFallback(image_id, mapping_id, range)
```

This prevents a modified executable page from being explained using stale file
bytes. A fallback is valid only when module identity, file offset, permissions,
and unchanged-byte evidence satisfy an explicit policy.

### Types and symbols

Use one type graph and symbol vocabulary, but represent assertions separately:

```text
EvidenceFact<T>
  subject identity
  value: T
  claim kind
  source artifact or analysis
  scope and lifetime
  confidence or proof status
  completeness dependencies
  derivation
```

A DWARF type, ABI-inferred type, analyst type, allocator-observed extent, and
trace-derived function target are not competing unlabelled writes to the same
field. They are evidence that a resolver can order or present according to
declared policy. Manual precedence remains intact.

### Completeness

Share the outer vocabulary—complete, partial, unknown, unsupported, denied,
truncated, raced, or budget-exhausted—but retain domain-specific detail:

- static: undiscovered blocks, unresolved indirect target, missing debug info;
- capture: omitted page, disappeared thread, permission denial, changed map;
- trace: dropped events, provider blind spot, sequence gap;
- replay: unsupported instruction or external effect; and
- symbolic: solver unknown, path bound, memory-model limitation.

No consumer may turn one domain's completeness into another's. A complete core
import does not imply complete execution history.

## Structures that must remain runtime-specific

### Execution identity and time

Every observed fact belongs to an execution scope:

```text
ExecutionId
ProcessInstanceId
ThreadInstanceId
SnapshotId or EventPosition
```

OS PIDs and TIDs are attributes, not durable identities: they are reused. An
event position is not just a wall-clock timestamp. It includes per-thread
sequence and provider ordering/loss information; cross-thread order exists only
where the acquisition mechanism or synchronization evidence establishes it.

Decompiler SSA must not be extended with PID, TID, or timestamp fields. The
join belongs in a runtime occurrence record:

```text
OperationOccurrence
  execution, process, thread, event position
  static FunctionIR operation identity when resolved
  runtime PC and code-byte origin
  observed inputs, outputs, and memory effects
```

A runtime write may first resolve only to the static callsite that caused an
interposed library effect. That is a useful typed relation, but it becomes an
`OperationOccurrence` only when occurrence scope and concrete inputs, outputs,
and effects attach to exactly one authoritative static operation identity.
Effects distinguish runtime-object identity from OS-resource identity; a heap
allocation is not a descriptor merely because both can participate in an
operation.

All current producers use one occurrence constructor. It derives the durable
ID from capture, process, thread, event sequence, exact image, function, LLIR
block, operation index, and operation kind. It rejects missing or cross-process
thread/event/object identities and a static operation from another image. This
keeps input, IOCTL, stack-write, and heap-write analyzers from inventing subtly
different identity rules.

Input-byte identity also remains separate from recovered storage identity. The
first source-to-field relation maps an occurrence's introduced source range
through its concrete LLIR call effect onto realized DWARF field intervals. It
retains source offsets, runtime addresses, object offsets, and field offsets as
distinct coordinates. It does not rename the source as a variable, store input
provenance in the static field/type record, or imply propagation beyond the
observed write effect.

Downstream provenance is likewise a relation, not a property added to an LLIR
temporary. The first `input_value_flows` producer records source-relative byte
spans and occurrence-scoped concrete loads/writes while reusing immutable LLIR
value expressions and the target register-view model. Intermediate memory
provenance is runtime versioned: an observed store consumes the prior version,
clears its destination, and creates a new version only after byte agreement.
It accepts a composed
partial-register expression only when the non-source portion provably
contributes no bits to the observed destination bytes. If the source location,
captured bytes, static slice, or observed write disagree, the relation is
unknown; runtime bytes never replace static operation semantics.
Nor does a backward slice create a load occurrence. The separate
`executed_loads` stream creates one only from the load instruction's own traced
PC, sequence, pre-instruction registers, exact LLIR identity, and concrete
effective address. The flow relation then requires that occurrence to fall
between the relevant memory-version creation and consuming store.

Observed blocks follow the same rule. A static native or LLIR block remains an
immutable candidate unit; it does not gain counts, timestamps, or an
`executed` bit. A separate occurrence joins one capture/process/thread sequence
range and its exact instruction PCs to one native block and one lifted block.
Linear instruction continuity, not equality of block address alone, extends an
occurrence, so a loop re-entry creates a new identity. Missing or interior PCs,
sequence gaps, ambiguous ownership, and unavailable lift semantics terminate
the occurrence and remain explicit unknown relations. Trace absence never
deletes a static block or edge.

Replay seeding is an adapter across this boundary, not a new owner of captured
state. Occurrence-time register evidence is projected through the shared
register model into a fresh concrete machine. Time-scoped object snapshots and
verified intervening deltas initialize a separately owned execution-memory
copy; they do not mutate the capsule or `ProgramImage`. The seed retains its
capture, thread, event position, observed-block relation, source snapshot
identity, reconstructed hashes, and exact initialized ranges. The execution
engine's unset-byte zero is never evidence that an omitted runtime byte was
zero: the runtime replay layer must stop as unknown before any access outside
those ranges.

Bounded replay reuses LLIR operation semantics but keeps architecture/runtime
transitions in the adapter. Raw LLIR `Call` and `Return` describe semantic
control flow; an opcode-proven x86-64 runtime occurrence may additionally push
or consume a concrete return address and update its separately owned machine
state. Likewise, a static VA produced by LLIR is not rewritten with a load
bias. A terminal comparison may relate it to an observed runtime VA only when
the immutable image and exact capsule mapping prove the equivalence, and the
relation retains both addresses and the mapping ID. `Op::Undef` remains unknown
state: replay reports the poison reason instead of treating the executor's
backing value as a runtime prediction.

Replay disagreement is owned by the replay occurrence, not written back as an
LLIR defect or runtime observation. Its first-divergence record may reference
an immutable LLIR operation identity and separately retain replayed and
observed values. Missing environment and unsupported semantics are distinct
from value disagreement; all three can stop the attempt without changing the
static operation or captured evidence that was compared.

Counterfactual query selection follows the same ownership rule. Byte
provenance, register taint, concrete memory addresses, event order, and the
observed branch direction belong to one runtime occurrence. LLIR contributes
immutable operation identities and transfer semantics. A separate candidate
relation may join them and retain exactly which source-byte spans reached
which predicate registers at which event. It must not mark an LLIR value, a
static CFG edge, a decompiler variable, or a `ProgramImage` object as globally
tainted. A conservative barrier withholds a candidate; it is not evidence that
the static branch is input-independent.

The counterfactual machine is another derived occurrence, not a mutation of
either side. It copies captured register and memory evidence into a fresh
symbolic machine, substitutes symbols only for the candidate's source-byte
spans, and references the immutable LLIR operations it replays. Its path
constraints, solver backend, model, proposed byte mutations, and predicted
edge belong to the counterfactual relation. A later real execution is a new
capture that may validate the prediction by identity; its observations do not
become the symbolic machine's state. Solver absence, resource limits, missing
environment, symbolic pointers, unsupported semantics, and privacy policy
remain distinct outcomes and never alter the static CFG.

The relation must also say whether a solver proposition was constructed. Once
constructed, SAT, UNSAT, and unknown retain the same exact path-condition
operation identities and event, memory, input, and solver bounds. A failure
before construction is `not_constructed`; it must not carry invented bounds or
be paraphrased as an infeasible path.

Validation likewise stays relational. A solver witness may propose a byte
patch; applying it creates a new process execution with a new capture identity.
The validating edge, corrupted field, or dangerous output belongs to that new
execution and may be joined back to the proposal by binary identity, input
patch, and static operation identity. It must not be copied into the original
capture or treated as an observed property of the symbolic machine.

Persistence preserves the same split. A `.glaurung` run may own multiple
immutable captures; each capture owns its processes, threads, modules,
mappings, and events. Those rows may reference immutable image identities, but
they must not be stored as fields on `ProgramImage`, LLIR operations, static
CFG edges, or decompiler variables. Provider event sequence is persisted in
its process/thread scope and is not upgraded into cross-thread causality.

The first instruction-step provider follows the same boundary. Its ordered
runtime PCs, hash-bound byte changes, and pre-instruction registers remain
execution evidence. Its LLIR store and bounded address-expression slice are
immutable static semantics; the join is an occurrence relation. The existing
DWARF object/field relation consumes that occurrence rather than copying
runtime addresses or values into decompiler variables. Destination containment
and source-expression bounds remain distinct relations: an out-of-bounds
`data[8]` store can concretely land inside `canary` without either fact replacing
the other.

Static operation semantics may retain a bounded expression for the stored
value as well as the address. Concrete values still belong to an occurrence.
This lets a relation classify an observed zero-byte store into a `char[]` as a
terminator without writing that observed value into LLIR or the decompiler AST.
Conversely, snapshot-derived changed bytes remain valid when operation
attribution is unknown; lack of one inferred join does not erase independent
observed evidence.

Width-changing expressions follow the same split. LLIR may preserve an
immutable truncation, extraction, or bit-mask expression and its operand
widths. The values before and after that expression, the registers used to
resolve its frame load, and the later write extent remain occurrence-scoped.
A runtime relation may join those facts to distinct DWARF scalar objects and a
subsequent memory effect, but it must not write the concrete value into the
static variable or identify CFA and RBP/RSP offsets by spelling alone.

The same prohibition applies to allocation substructure. An observed allocator
object keeps its concrete address, full extent, and lifetime. If a static call
argument and DWARF scalar prove that the program treated a prefix as a logical
extent, that prefix is a relation over the runtime object, not a replacement
object size. A write can therefore cross the logical prefix while remaining
within the allocator extent; collapsing those claims would turn source intent
into false allocator metadata.
Snapshots immediately bracketing one write occurrence may separately establish
that the prefix and reserved tail changed. That is runtime byte history, not a
new allocation extent and not ownership by a decompiler variable. A separate
executed-operation relation must prove any source-storage identity for the tail.
The first such heap relation comes from a bounded instruction trace. The static
store keeps its address and stored-value expressions; the occurrence keeps its
register-derived address and effect; DWARF keeps the pointer-local contract;
and ordered runtime-object snapshots keep the bytes. Their typed join may say
that source pointer `canary` addressed bytes which later changed, but none of
those domains becomes the storage container for another. A separate capture
identity cannot be promoted into the same temporal chain merely because its
static operation identities match. Conversely, sharing one real capture does
not collapse several occurrences into one: allocation, a direct store, and a
later library write keep distinct operation identities. An aggregate object
diff is attributed to one occurrence only when that occurrence's bounded
effect covers every changed byte.
Placing events from two acquisition mechanisms on one sequence additionally
requires an observed synchronization boundary. Provider-local sequence numbers
prove order only within that provider; checkpoint high-water marks prove which
trace interval contains them. Source statement order is not runtime evidence.
For compound store addresses, walking an LLIR slice may discover several static
frame-slot loads. A runtime source-pointer relation may select a unique
pointer-typed DWARF local from those candidates; it must not label an index
scalar as a pointer or rewrite the compound expression into the static model.
The selected pointer's concrete value must be reconstructed at the occurrence,
not read from an unqualified checkpoint. The current heap-index relation starts
from a hash-bound stack snapshot and applies every preceding ordered stack
change before decoding the pointer. It then joins that pointer to the observed
allocator object and a separate allocation occurrence. The allocation's static
`Load(n) + 8` argument and DWARF scalar `n` establish a logical prefix relation;
the allocator object retains its full observed extent. A store crossing that
prefix is not, from those facts alone, proof that the adjacent bytes belong to a
source variable named `canary`.
The next relation supplies that missing evidence independently. It reconstructs
fixed-width DWARF pointer locals at the same occurrence and requires exactly one
value equal to the derived tail start. Only then may snapshot bytes be described
through that source pointer. The relation still does not turn `canary` into the
allocator object, shrink the allocation, or annotate a static variable with a
concrete address. Unsupported or ambiguous pointer contracts remain unknown.

The same rule applies to calls. A static operation may retain an immutable
direct or indirect call-target expression and a relocation-proven import name.
It also owns stable identities for the target semantic value and for each
statically recovered ABI-input expression and semantic value. Direct targets
do not acquire a fabricated expression merely to make the graph uniform.
Pre-call registers, ABI argument values, concrete destination objects, and
logical memory effects belong only to an `OperationOccurrence`. The first
`memcpy` relation follows this split: static LLIR says which call target exists;
one hash-bound trace says which arguments this execution supplied; DWARF says
what field contract applies; endpoint snapshots say which bytes actually
changed. None of those facts is copied into another domain's container.
For implicit-length calls such as `strcpy`, the derived length is an occurrence
input supported by a time-scoped captured snapshot; it is not added to LLIR as
if the machine instruction encoded it. Likewise, bytes touched by the logical
effect and bytes whose values changed are separate relations.
`strcat` additionally demonstrates why one generic “length” is insufficient:
the pre-call destination extent determines the concrete write start, the source
extent determines bytes appended including the terminator, and their sum is
the final string extent used by the field-bound conclusion. All are dynamic
occurrence facts; only the imported call identity belongs to static LLIR.
Implementation follows the same rule through typed call contracts. A library
name selects a semantic shape, the shape derives occurrence-scoped extents from
ABI and snapshot evidence, and only then may the common relation builder attach
an effect to a runtime object. Unsupported calls remain unknown rather than
falling through to a superficially compatible argument layout.
For `sprintf`, relocation-proven call identity is still insufficient to infer
an output extent. The occurrence contract separately requires captured format
bytes and selects the variadic ABI argument only after proving the supported
`%s` shape. A source-level literal or fixture name cannot substitute for that
runtime evidence.
Overlap classification follows the operation contract, not changed bytes
alone. Equal concrete ranges are permitted for a `memmove` occurrence and
violate the `memcpy` precondition. The source/destination ranges and result are
runtime relations; the immutable call kind remains static semantics.

### Mappings and module instances

A runtime module is one load instance, not the static image itself. Multiple
instances of one image may have different load biases and process scopes. A
mapping may be file-backed, copied, modified, deleted, anonymous, aliased, or
partially captured.

`RuntimeAddress` therefore carries at least:

```text
process instance
raw virtual address
mapping identity
module instance when resolved
module-relative address when proven
static image and address when proven
snapshot/event scope
resolution verdict and ambiguity reason
```

ASLR subtraction is an output of a proved mapping relation, not an address
constructor.

### Sparse captured memory

`ProgramImage` bytes are immutable and file-relative. Runtime memory is sparse,
permissioned, time-scoped, and may be racy. Pages require capture status,
content hash, and omission reason. A read must distinguish:

- bytes observed in this snapshot;
- an explicit, proven static fallback;
- partially available bytes;
- an unmapped interval;
- a mapped but uncaptured interval;
- access denied;
- a mapping race; and
- arithmetic or request-budget failure.

The existing `MemoryView::read_bytes() -> Result<Vec<u8>, MemoryError>` is a
useful static seam but cannot express this contract. Do not overload
`MemoryError::OutOfRange` to mean every runtime absence. Introduce a richer read
result or a runtime-specific extension and adapt it to the old trait only for
consumers whose loss of provenance is explicitly safe.

### Allocation and object lifetime

A recovered decompiler variable is not a runtime object. A runtime object has
an allocation instance, address extent, creation/destruction evidence, owning
process, allocator/provider, and confidence. Stack frames recur; heap addresses
are reused; mappings change protection and backing.

The capsule therefore stores runtime objects and their object-relative byte
snapshots at explicit event positions. Repeated snapshots of one address do not
become competing `ProgramImage` bytes or static MemorySSA versions. They remain
runtime evidence until a separate relation proves a connection to a static
storage identity, high variable, field, or operation.

Use a relation such as `RuntimeObjectRealizes(high_variable_id)` only when
frame, instruction, storage, and lifetime evidence justify it. Never key heap
objects by address alone or make allocator-specific metadata part of the
portable object identity.

For debug-proven variables, identity comes from the declaration DIE offset
inside the exact image; type identity comes from its referenced type DIE. A
rendered name, C-like type spelling, frame offset, or runtime address is an
attribute and cannot serve as identity. Optimized location ranges may change
without changing declaration identity. Pointer relations therefore join a
runtime object to IR-owned immutable variable, type, and semantic-binding nodes
without making the object, variable, semantic operand, and type the same
entity. The binding itself has an identity derived from its endpoints and
relation kind; it is not inferred from matching presentation strings.

Decompiler-recovered variables without a declaration DIE use a different but
equally explicit origin contract. An ABI parameter is identified within its
canonical function by ABI position and recovery profile. A promoted frame
local is identified by a unique proven frame base/displacement and recovery
profile. In this case the storage coordinate is part of the recovered origin,
not a substitute for a debug declaration identity. A rendered variable name
remains presentation only. If several candidates share a coordinate, or no
coordinate is proved, the analyzer emits no static-variable identity rather
than falling back to a name. A parameter's structured recovery hint may mint a
recovered type node whose identity derives from semantic shape, target width,
exact image, and recovery profile. Its C-like spelling is still presentation.
Stack locals currently retain only source/render text and access size, which is
not equivalent evidence, so they keep `type_id` absent.

An event after destruction still references the allocation instance ID when
the provider observed that identity before the address became reusable. It
does not revive the object, create a post-destruction snapshot, or become a
static variable. The event may prove a write-after-lifetime relation. A
separate source-pointer relation may additionally join an observed call
destination to a bounded static ABI-register input expression, an exact
semantic call contract, and one authoritative DWARF pointer slot. Register
presence alone never establishes call arity. The relation says the pointer value names the allocation
at this occurrence; it does not collapse the pointer variable and dynamic
allocation into one identity. Completeness for an interposed write family is
likewise separate from completeness for object lifetimes, snapshots, or
arbitrary machine stores.

### OS resources and events

Descriptors, files, sockets, processes, signals, syscalls, mapping transitions,
and environment observations are runtime-domain entities. They may reference
static call sites or semantic operations, but they do not belong in LLIR or the
decompiler AST.

## Relations instead of mutation

The correlation layer should express small typed relations:

| relation | example |
|---|---|
| `InstanceOf` | runtime module instance is an exact instance of static image SHA-256/build ID |
| `ResolvesTo` | runtime PC resolves to an instruction or block in `FunctionIR` |
| `ObservedEdge` | one execution transferred from block A to block B |
| `ObservedTarget` | indirect call at operation X reached address Y once |
| `ObservedValue` | operation occurrence had a concrete input or output |
| `RealizesStorage` | runtime register or memory range realizes a semantic storage location at one occurrence |
| `RealizesObject` | runtime allocation/frame object corresponds to a recovered program object under stated evidence |
| `Corroborates` | runtime evidence supports an existing static fact |
| `Contradicts` | observed bytes, target, or effect conflicts with a static assumption |
| `DerivedFrom` | finding or inference names its source observations and transformations |

Relations are append-only evidence records for a captured artifact. Derived
views may select the best current interpretation, but must retain the underlying
facts.

## What must not happen

The following are design violations:

1. Adding captured pages to `ProgramImage.bytes` or replacing its bytes in
   place.
2. Treating a process virtual address as an image VA without an exact mapping
   relation.
3. Treating one observed indirect target as the complete static target set.
4. Removing a static CFG edge because a trace did not execute it.
5. Assigning one concrete value directly to a decompiler SSA value without an
   execution occurrence, including loop iteration and thread scope.
6. Using a recovered stack local as the identity of every dynamic frame's
   corresponding object.
7. Storing runtime evidence only as comments or annotations on AST nodes.
8. Converting a missing page into zero bytes or silently reading the file image.
9. Converting a complete snapshot into a claim of complete execution history.
10. Letting runtime-derived types or names overwrite analyst facts without the
    existing provenance and precedence rules.
11. Representing PID, path, basename, load bias, or raw address as sufficient
    module identity.
12. Creating a second runtime-only symbol, type, finding, or provenance system.

## Interaction with `FunctionIR`

The proposed central function graph and runtime model solve different problems:

- `FunctionIR` says what a function means and records possible program
  structure under static evidence.
- `OperationOccurrence` says what happened at one operation in one execution.
- `CorrelationGraph` relates the two without changing either claim.

The first implemented `FunctionIR` identity primitive is a canonical hierarchy:
exact image plus lift-profile generation names a function, the function names a
block, and the block plus operation index and kind names an operation. Every
`OperationOccurrence` must carry those three IDs and recompute them
successfully; a forged or stale parent or operation ID becomes unknown.
Capture, process, thread, and event sequence remain exclusively in the
occurrence ID, so two executions can share one static operation without sharing
runtime state. Address and stored-value expression roots now receive distinct
operation-owned IDs when those immutable LLIR slices exist. Every nested node
also has a deterministic typed child path, parent ID, root ID, and semantic
kind. Occurrence construction recomputes the complete graph, so missing,
invented, or reordered nodes fail closed. These are semantic identities, not
rendered-token identities. The address and stored-data operands also receive
distinct static value IDs linked to their operation and expression roots;
condition and ordinary defined-value roots use the same vocabulary. Concrete
values still belong only to occurrences. Call operands, variables, types,
AST-origin relations, and token links remain open.

Runtime observations may trigger a new static-analysis generation—for example,
reanalyzing an indirect jump with an observed target as non-exhaustive evidence.
The resulting graph must cite that evidence, retain alternative targets, and
use a new analysis version. It must not mutate the old graph in place or label
the observed target exhaustive.

The implemented null-access semantic projection is the minimal positive
example. It relates an observed zero fault target and proven runtime direction
to an exact static instruction containing exactly one corresponding LLIR
load/store with a known positive width. The relation may derive
`read:null:width=N` or `write:null:width=N`; it must not copy that width into
the runtime event, attach the fault address to the LLIR operation, or select one
operation when static resolution is ambiguous. Failure of any premise produces
an unsupported semantic fact rather than a partially guessed join.

Parent/child lifecycle evidence follows the same rule on the runtime side. A
process-creation result and parent-side wait result may be related by a
capture-scoped OS PID, but that PID is neither a static identity nor evidence
for uncaptured child state. The relation may count coherent created/reaped
occurrences; it must not synthesize child threads, mappings, modules, terminal
status, or transitive descendants.

Observed conditional control follows the same boundary. LLIR may expose a
condition expression, direct target, and stable operation identity. A capture
may append an `ObservedEdge`, observed successor, and occurrence-scoped
call-result dependency. It must not mark that edge as the only static edge,
store the concrete return value on the LLIR call, or let a backward slice cross
an unmodelled call. The Linux x86-64 correlation layer may apply the SysV
result-register contract, but it must withhold the relation after an
intervening clobber or call.

A branchless conditional selection has the same split. LLIR owns the `Ite`
alternatives, condition dependency, and defined/used registers. A runtime
occurrence owns the selected concrete output and register-continuity evidence.
The correlation layer may derive an input-to-sink relation from both; it must
not turn the observed alternative into a permanent static constant or invent
an observed CFG edge for a conditional move.

Ordinary value definitions follow that boundary too. LLIR may own a register
definition and a bounded expression such as a constant assignment or
zeroing XOR. A `value_definitions` occurrence may retain the pre/post register
evidence and whether the observed output agrees. A mismatch with one trace
withholds that occurrence relation; it does not replace the static expression,
mark the instruction invalid, or attach the concrete value to every execution.
Likewise, a concrete spill/reload address belongs to the occurrence flow while
the load/store address expressions remain static.

OS context may be joined at projection time without becoming instruction
semantics. A stopped-child descriptor snapshot may reveal only explicitly
allowlisted targets and must retain its raced completeness. It may contextualize
an exact ioctl occurrence, but it must not imply that the trace observed the
earlier open, attach a path to the static call, or establish completeness for
unrelated file events and findings.

## First vertical slice

Use `crash_null_write` as the first end-to-end model test because it requires a
small but real cross-domain chain:

```text
core or stopped child
  → ProcessCapsule and sparse pages
  → faulting process/thread/registers
  → RuntimeAddress at PC and fault address
  → exact module/image correlation
  → decode and FunctionIR operation resolution
  → observed memory access with null target
  → crash classification and evidence packet
```

The negative controls are as important as the success path:

- wrong executable hash must reject static correlation;
- omitted PC page must remain incomplete unless proven fallback is requested;
- missing fault address must prevent a precise access classification;
- a good scenario must not produce a crash finding; and
- the evidence packet must distinguish kernel observation, static resolution,
  and inferred explanation.

After that slice, the other four seed cases add one concept at a time:

| case | additional model pressure |
|---|---|
| `crash_bad_function_pointer` | indirect control target and execute fault |
| `memory_struct_field_overwrite` | before/after state, dynamic object, byte interval, and non-crashing finding |
| `danger_rw_to_rx` | ordered mapping-protection events and OS semantics |
| `normal_open_file` | syscall/resource evidence and a false-positive control |

## Acceptance tests for the design

Before implementing the broad roadmap, prototypes must demonstrate:

1. The same static image can correlate with two simultaneous process/module
   instances without address collision.
2. One LLIR/`FunctionIR` operation can have distinct occurrences and concrete
   values across threads and loop iterations.
3. Runtime-modified executable bytes decode from the captured page and do not
   poison or overwrite the static image.
4. Missing runtime bytes remain missing unless a named fallback policy proves
   and records substitution.
5. An observed indirect target augments but does not close the static target
   set.
6. A complete snapshot with no history cannot answer whether a past write
   occurred.
7. A type or name conflict preserves both facts and applies the existing manual
   precedence policy.
8. Serializing, importing, and exporting a capsule preserves identity,
   provenance, extensions, and completeness deterministically.

These tests decide whether the shared-kernel boundary is workable. If they
require pervasive PID/time fields inside LLIR, or if runtime pages must mutate
`ProgramImage`, the abstraction is wrong and should be revised before expanding
the implementation.
