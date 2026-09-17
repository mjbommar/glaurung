# Runtime crash report

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/crash.rs` joins a validated `ProcessCapsule` and exact
`ProgramImage` into `glaurung-runtime-crash-report-v1`. The first product-facing
surface is `glaurung.runtime_analysis.analyze_process_capsule_crash`.

The report identifies one signaled process and one provider-identified faulting
thread. It retains the observed signal, architecture, PC, SP, and fault address.
The process and thread signals must agree. Missing or ambiguous process, thread,
or register evidence produces an incomplete or unknown result.

For Linux cores, the fault record and report preserve `siginfo` code and the
sender PID/UID union fields for user-origin signals. A non-positive user-origin
code plus a sender PID equal to the crashed process supports
`deliberate_signal:SIG*`. `SIGABRT` is intentionally excluded from that generic
class because those signal facts alone cannot distinguish `abort()` from a
failed assertion.

Complete, hash-verified stderr containing the C runtime's assertion diagnostic,
combined with self-generated `SIGABRT`, supports `assertion_failure`. Missing,
truncated, non-UTF-8, or identity-mismatched output weakens both the output and
classification to unknown. Empty stderr is not treated as proof of explicit
`abort()`.

For Linux x86-64, `explicit_abort` requires an additional independent chain:
the captured frame-pointer walk must contain a runtime return address that
resolves into the exact static image, the five preceding static bytes must be
an `E8 rel32` direct call ending at that return address, and the computed target
must be the relocation-backed ELF `abort@plt` entry. The signal must also be a
self-generated `SIGABRT`. A missing stack frame, mapping, instruction, or PLT
identity leaves the class unknown; stderr silence is never substituted.

The report also retains the bounded provider register set for the faulting
thread and requests three fixed 32-byte memory windows: centred on PC, forward
from SP, and centred on the fault address. Window bytes are observed only when
the sparse runtime memory view can satisfy the entire request from captured,
hash-verified page payloads. Unmapped, unreadable, omitted, boundary-crossing,
and unavailable windows remain individually unknown with the precise reason.
The report never substitutes static executable bytes for missing runtime bytes.
These fields can contain sensitive process data and inherit the capsule
payload's handling requirements.

On x86-64, `native_stack` performs a bounded frame-pointer walk over captured
runtime bytes. Frame zero is the observed fault PC. Later frames are explicitly
marked `frame_pointer_chain`, record the return-address slot, and independently
attempt exact runtime/static location resolution. The walk is capped at 32
frames and rejects non-increasing, unaligned, implausibly large, unreadable, or
truncated steps. Its stop reason is retained. This is not DWARF/CFI unwinding,
and it does not claim that every optimized caller is present. Other
architectures remain unsupported rather than borrowing x86-64 layout rules.
When a `SIGSEGV` fault target equals SP, is unmapped, and all 32 validated
frames resolve to one repeated static function before the bound is reached,
that combined evidence supports `recursive_stack_exhaustion`. Neither a deep
stack nor `SIGSEGV` alone is sufficient.

The PC is passed through the exact runtime/static correlation relation, which
retains module and mapping identity, normalized addresses, byte origin,
function, basic block, instruction, and LLIR operations. An access direction
provided by the capture remains observed. When it is absent, one unambiguous
static LLIR load or store class may support an inferred read or write. The
report never labels that inference as an observation.

For product consumers, `location` projects an exact relation into one compact,
evidence-labelled module, mapping, runtime/static address, function, block, and
instruction summary. `static_location` remains the authoritative detailed
relation. The projection becomes unknown unless the module identity, containing
function, block, and instruction are each uniquely resolved; it never fills
missing fields from symbols or address guesses.

The crash classifier combines a zero fault address with a proven access
direction to report `null_read`, `null_write`, or `null_execute`. If the fault
target equals the observed PC, that relation supports inferred execute access.
Together with an exactly containing captured mapping, a proven access direction
supports `read_protection_fault`, `write_protection_fault`, or
`execute_protection_fault`; an unmapped execute target supports
`invalid_control_target`. These are permission and target classifications, not
claims that an anonymous inaccessible mapping was intentionally a guard page.
Proving that role requires ordered evidence that the same process range was
created and then deliberately protected inaccessible before the fault.

The oracle-independent semantic-result projection can make the null memory
access one step more precise without changing either source model. For a
`null_read` or `null_write`, it requires an observed zero fault address, the
proven access direction, an exact static-location relation, and exactly one
resolved LLIR load or store of the corresponding kind with a positive byte
width. Only that complete join emits `read:null:width=N` or
`write:null:width=N`. Missing, ambiguous, mismatched, or widthless LLIR
operations leave the precise access fact unsupported. The runtime report does
not acquire a static width, and the LLIR operation does not acquire a runtime
occurrence; the semantic fact cites the evidence-bearing join.

The first traced-core provider supplies that evidence as normalized capsule
events. `guard_page_read` or `guard_page_write` requires a successful anonymous
read/write `mapping_create`, followed on the same event stream by a successful
`mapping_protect` with no permissions, with both ranges covering the concrete
fault address. The final mapping must independently deny the proven access.
The analyzer has no tracer-specific branch and does not inspect raw trace text.
Removing, reversing, or weakening the event chain leaves the ordinary
read/write protection class. A core snapshot contains only final mappings, so
adjacency, page size, or anonymous backing cannot close that gap by itself.

The real-core gates cover `crash_null_write` across GCC/Clang, `-O0`/`-O2`, and
PIE/non-PIE, plus all 15 GCC `-O0` PIE crash cores. All 15 crash shapes currently
receive evidence-backed classes: null read/write, inaccessible read/write,
read-only write, non-executable execution, an unmapped control target, and
recursive stack exhaustion, five self-generated signals, failed assertion, and
explicit abort. The same 15-core gate evaluates the independently produced
semantic results; its null-read case rejects a mutation of the joined LLIR
width. Two additional real traced-core gates establish intentional
guard read/write without changing the weaker core-only classification. CFI
unwinding remains open.

`glaurung.runtime_analysis.render_process_capsule_crash` runs the same typed
analysis and produces deterministic analyst-readable text. It preserves each
field's observed, inferred, or unknown status and its source or reason. Because
memory windows and process output may contain secrets, the text reports only
their availability and byte counts. It never includes their contents. Callers
must explicitly request the typed JSON surface when they are authorized to
handle those bytes.

`glaurung-runtime-crash-comparison-v1` analyzes a completed good-control capsule
and bad-case capsule independently under the same exact `ProgramImage`. Its
typed contrast distinguishes `bad_only`, `good_also_crashed`,
`bad_did_not_crash`, and incomplete inputs. A `bad_only` result carries the
bad report's evidence-labelled class, including `unknown`; comparison never
upgrades weak classification evidence. The 15-case core gate pairs every bad
crash with a fresh terminal-result good control and requires `bad_only`.
