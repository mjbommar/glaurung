# Runtime process behavior

> **Kind:** architecture · **Status:** maintained

The bounded Linux trace provider normalizes process creation and wait results as
`process_create` and `process_wait` capsule events.
`src/runtime_analysis/behavior.rs` consumes those provider-neutral events and
produces `glaurung-runtime-process-behavior-report-v1`, exposed through
`glaurung.runtime_analysis.analyze_process_capsule_process_behavior`. The
oracle-independent `process_tree_semantic_result` projection consumes that
typed report rather than reparsing capsule events.

A successful `fork`/`vfork`, or a `clone`/`clone3` carrying process-creation
semantics rather than `CLONE_THREAD`, retains the parent capsule-process
identity, caller OS TID, returned child OS PID, provider syscall, process/thread
occurrence scope, and kernel result. A wait observation retains the requested
PID selector and either the reaped OS PID or errno. Thread creation is
recognized but deliberately excluded from the
process-child relation. An in-scope process syscall whose provider spelling
cannot be normalized rejects acquisition.

These events do not manufacture child `ProcessSnapshot`s. The terminal trace
does not capture child registers, mappings, pages, modules, or terminal state;
an OS PID is not a durable process identity outside this capture. The events
only establish bounded parent-side lifecycle observations in one complete
provider scope.

The semantic projection requires complete `process_events` evidence, unique
created and reaped PID sets, and every reaped PID to have a creation identity in
the captured set. It then emits `children_created` and `children_reaped` counts.
Missing completeness, malformed identity, duplicate identity, or a reap outside
the created set makes both facts unknown. The typed analyzer also checks that
the completeness count equals the actual normalized process-event population;
dropping an event while retaining stale completeness therefore remains unknown.
The one-child control supports
negative `excessive_fork` evidence only within this fixture-bounded rule; the
model does not claim a universal safe process-count threshold.

The real `danger_fork_tree` gate covers one child in the good run and three in
the bad run. Both runs require the successful create and reap sets to agree,
and both satisfy their independent semantic oracles. Mutating the produced
creation count fails evaluation. Replacing a real reaped PID with an unknown
identity fails closed, and a synthetic `CLONE_THREAD` trace proves that threads
are not counted as child processes.

Open work includes child terminal outcomes, recursive descendants, exec
transitions, descriptor inheritance, process groups/namespaces, and stopped/live
child state. Those require additional capture evidence rather than inference
from the parent-side syscall count.
