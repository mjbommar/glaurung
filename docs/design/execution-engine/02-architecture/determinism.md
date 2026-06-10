# Determinism & Reproducibility

A Glaurung house rule (no `Date::now`/`Math.random` in analysis paths) **and** a
correctness requirement for symbolic execution (KLEE relies on deterministic
replay; "code that depends on memory addresses won't replay" if allocation
wanders). Every component below is constrained by this.

## Rules

1. **No host time, no host randomness in execution paths.**
   - `RDTSC`/`RDTSCP` → a **virtual monotonic counter** derived from the
     instruction count, via a helper.
   - `CPUID` → a **fixed, configured** feature set (never the host's).
   - `RDRAND`/`RDSEED` and any random/time/PID syscall → a **seeded deterministic
     PRNG** (seed is part of the run config, surfaced and logged).
   - Route every nondeterministic instruction/syscall through a helper that reads
     only emulator-internal state ([`helpers-and-intrinsics.md`](helpers-and-intrinsics.md)).

2. **Deterministic memory allocation.** The modeled allocator (`malloc`, `mmap`,
   `ExAllocatePool`) is a **bump/segmented allocator with fixed base addresses**.
   Two runs of the same input produce identical layouts, so symbolic witnesses and
   concrete results replay exactly.

3. **Ordered worklists everywhere.** Never iterate a `HashMap`/`HashSet` where
   order affects output. The symbolic explorer uses a `BinaryHeap` keyed on
   `(priority, state_id)`; CFG/lift iteration is sorted by VA (matching the
   existing `lift_function` which already "sorts blocks by VA for determinism").

4. **Stable tie-breaking.** Equal-priority states break ties on monotonic
   `state_id` (creation order). Equal anything breaks on a stable key, never on
   address or hash iteration order.

5. **Pinned solver configuration.** Fixed random seed, fixed tactic, single
   thread (or fixed thread scheduling). SMT solvers are reproducible only when
   seeded. Across the pipe backend, pass `(set-option :random-seed N)`.

6. **No wall-clock control flow.** Budgets are **instruction counts**, not
   timeouts, for the deterministic core. (A wall-clock *safety* cap may abort a
   runaway run, but it must not change results on a run that completes — it only
   ever turns a would-be-complete run into an explicit `Halt::Timeout`, surfaced,
   never silently truncating.)

## Parallelism & determinism

Path exploration can be parallelized (one solver context per worker — no shared
contexts allowed anyway). To stay deterministic under parallelism: assign work by
stable `state_id` partitioning and **merge results in `state_id` order**, so the
output is independent of which worker finished first. If perfect determinism under
parallelism proves costly, default to single-threaded exploration and make
parallelism an explicit opt-in that documents its (still-bounded) nondeterminism.

## Testing determinism

A dedicated test runs each engine entry point **twice** on the same input and
asserts byte-identical output (register dumps, witnesses, resolved targets, KB
writes). This is cheap and catches accidental `HashMap`-iteration or host-entropy
leaks early. → [`../04-testing/README.md`](../04-testing/README.md).

## References
- [`../01-research/symbolic-execution-survey.md`](../01-research/symbolic-execution-survey.md) §8
- [`../01-research/emulator-engineering.md`](../01-research/emulator-engineering.md) §7
