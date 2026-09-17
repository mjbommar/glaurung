# Runtime object change report

> **Kind:** architecture · **Status:** maintained

`src/runtime_analysis/corruption.rs` produces
`glaurung-runtime-object-change-report-v1` from a validated `ProcessCapsule`
and its external payloads. The Python surface is
`glaurung.runtime_analysis.analyze_process_capsule_object_changes`.

For each runtime object, the analyzer selects the earliest and latest snapshots
only when they belong to one ordered event stream and cover the same
object-relative interval. Both payloads must match their recorded length and
SHA-256. Missing, omitted, differently scoped, differently sized, reversed, or
identity-mismatched evidence produces an explicit unknown result.

Changed bytes are emitted as maximal contiguous object-relative intervals with
their before and after bytes. These are observed byte changes, not automatic
overflow findings. `responsible_write` becomes an observed event attribution
only when exactly one bounded `memory_write` event in the same object and event
interval covers every changed byte. Zero or multiple covering events, partial
coverage, unavailable changes, and absent ordering remain unknown. This is an
event attribution. When that event also resolves to exactly one static LLIR
call operation, the report emits a separately typed `OperationOccurrence` with
the observed destination and length as inputs and a `memory_write` effect that
references the runtime-object ID. The effect does not overload an OS-resource
ID, and an uncaptured call return remains explicitly unknown. Runtime objects
are not equated with recovered variables, fields, or static MemorySSA versions;
those require later correlation relations.

Allocation events follow the same occurrence boundary. The bounded heap
provider records the actual `calloc` count and element size, caller return
address, and loader-observed main-module bias. When that evidence resolves to
one exact imported `calloc` call, the report retains a creation callsite and an
`OperationOccurrence` whose `memory_allocate` effect names the concrete runtime
object. The pointer result is represented by that typed effect rather than
forced through the occurrence model's signed integer output field.

The occurrence is built through the same canonical constructor as input and
IOCTL occurrences. That constructor verifies process, thread, event, image,
and runtime-object scope before deriving the ID from the static operation and
execution occurrence. A relation cannot silently attach an object owned by a
different process or an operation from a different image.

The report also retains every bounded `memory_write` event that names the
object, including events after its recorded destruction. Each
`write_observation` classifies the event as `before_lifetime`, `live`, or
`ended` from the object's event-scoped creation and destruction positions. Its
object-relative range, hash-verified post-write bytes, exact static callsite,
and operation occurrence remain independently evidenced. A missing byte
payload makes only the post-write value unknown; it does not erase the observed
event, lifetime ordering, or a separately proved static relation. No snapshot
is created after destruction, because doing so would represent invalid storage
as a live object state.

The heap provider declares `heap_object_writes` completeness separately from
allocation-lifetime and snapshot completeness. That scope currently means
interposed `memset` calls whose destination begins within an allocation
instance observed by this provider; it is not completeness for arbitrary
machine writes. Consumers must not use it to assert absence outside that
scope.

For a Linux x86-64 ET_EXEC or PIE image, a uniquely attributed write event may
also yield `static_callsite`. The provider records the loader-observed main
module PT_LOAD extent and `dlpi_addr` load bias, and accepts the caller only
when its return address falls inside that extent. The analyzer requires the
capsule executable SHA-256 to match the `ProgramImage`, subtracts the observed
ELF load bias, and requires the result to be exactly five bytes after a decoded
static `call` instruction in the containing function. The result retains the
function, block, instruction, and stable LLIR operation relation. This is a
proved provider observation, not subtraction of a presumed ASLR base. Wrong
images and tampered load biases retain the observed write but make the static
callsite unknown.

The first real gate uses `memory_heap_canary_overwrite` in good and bad modes.
Its bounded `calloc` object begins as zeroes. At `free`, the good run differs in
interval `7..12`, while the bad run differs in `8..12`. This proves real
object-relative before/after reporting and the useful partial-attribution
boundary. It does not yet prove which subobject was corrupted, whether a bounds
violation occurred, or which instruction performed the write.

The `memory_underallocation` gate supplies the first exact write-event case.
In the bad run, one 16-byte `memset` event covers the complete observed `0..16`
change. In the good run, independently initialized bytes extend beyond that
event, so the analyzer correctly refuses whole-change attribution. Neither
result claims that the allocation object itself was overrun.
The PIE and non-PIE bad lanes additionally resolve the `memset` invocation to
an exact static instruction and LLIR `call`, then attach the concrete object
write to that one execution-specific occurrence. Wrong-image and tampered-bias
controls preserve the observed event but make both the static callsite and
occurrence unknown. The relation identifies the semantic call responsible for
the observed interposed effect; it does not mislabel the call operation as the
internal byte-store implementation.

The next relation preserves the smaller source-derived prefix without changing
the runtime object's identity or extent. The exact `calloc(1, size)` occurrence
has a bounded static element-size expression `Load(n) + 8`; the load must match
one DWARF scalar local, and the observed element size must equal the runtime
object extent. A subsequent exact `memset` occurrence must write from the
object start through a separately proved source pointer `p`. The resulting
`allocation_prefix_write` records both the real allocator extent and the
derived prefix/tail split. In the good run, a 16-byte write stays within the
16-byte prefix of a 24-byte object. In the bad run, the same write crosses an
eight-byte prefix by eight bytes while remaining within the 16-byte allocator
object. All eight GCC/Clang `-O0` PIE/non-PIE lanes agree. Wrong image, tampered
write bias, and stripped DWARF controls retain lower-level observations but
withhold this relation.

The provider also captures the bounded full object immediately before a live
observed `memset`. `allocation_prefix_transition` selects the nearest snapshots
before and after that exact occurrence and reports prefix changes, tail
changes, and tail endpoint bytes separately. It does not replace the creation
and final snapshots. A post-destruction write can retain ended-object identity,
but cannot create a snapshot after the object lifetime.

This is a source-derived prefix crossing, not proof that the allocator object
was out of bounds and not yet a complete adjacent-canary history. The runtime
transition proves which tail bytes changed, but it does not identify those
bytes as source `canary`. That still requires a separately proved executed
direct-store and source-pointer relation; byte-pattern or name matching does
not count.

`memory_stale_pointer_write` is the first temporal object gate. Across GCC and
Clang `-O0`, PIE and non-PIE, the good run has one live one-byte `memset`
observation and the bad run has that observation followed by a one-byte write
to the same allocation identity after its `free` event. The bad post-write byte
is `09`; removing its external payload preserves the ended-lifetime and static
operation evidence while making the byte value unknown. This proves a write to
an ended allocation instance. The exact LLIR call now also retains bounded
static expressions for candidate ABI register inputs. The exact `memset`
contract, not the presence of six SysV registers, establishes arity and names
the first input as the destination. In every lane, that observed destination
equals the allocation start and its static expression is a load from exactly
one DWARF pointer local named `p`; a separate
`source_pointer` relation records that join without turning `p` into the runtime
object. This exposed and corrected Clang pointer DIEs without an explicit byte
size being misread as the pointee's one-byte size rather than the compilation
unit's eight-byte address size.

The oracle-independent semantic projection satisfies both bad-case assertions:
the ended-lifetime byte change and `write_after_free` violation. Its good case
proves the live byte change but deliberately leaves broad absence of a
write-after-free unknown. Complete interception of in-object `memset` calls is
not complete observation of arbitrary machine stores.
