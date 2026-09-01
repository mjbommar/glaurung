# Phase 5 — Corpora for the modules with almost no tests

## The problem

Four modules that turn analysis into *answers a human reads* are effectively
untested (counts verified against the tree):

| module | test fns | files |
|---|---:|---:|
| `src/demangle/` | 1 | 1 |
| `src/similarity/` | 2 | 1 |
| `src/flirt/` | 4 | 1 |
| `src/target/` | 1 | 4 |

Meanwhile `src/ir/` holds 1,847. None of these four needs cleverness — each
needs a **corpus**, and for three of them the corpus can be generated from
assets the repository already builds, with an oracle we already trust.

## 5.1 Demangle: oracle-generated name corpus

One test today, for a component with three grammars (Itanium, Rust v0, MSVC)
that is also a classic panic farm on adversarial input (Phase 3 adds the
fuzz target; this adds correctness).

* `tools/gen_demangle_corpus.py`: harvest mangled names from binaries we
  already have — the C++ fixture objects, `libstdc++.so`'s dynamic symbol
  table, the Rust fixture objects (v0 mangling), and the Phase 4 PE lane for
  MSVC names. Demangle each at generation time with the reference tools
  (`llvm-cxxfilt`, `rustfilt`, `llvm-undname`), record `(mangled, expected)`
  pairs, commit as `tests/fixtures/demangle/corpus.jsonl`.
* Generating our own corpus rather than importing libiberty's test suite
  keeps licensing trivial and ties the corpus to symbols glaurung actually
  encounters.
* Table-driven test over the corpus, default suite. Target ≥5,000 pairs
  (a symbol table harvest gets there in one library); dedupe by mangled name.
* Divergences from the oracle found during generation are triaged **before**
  commit: each is either a glaurung bug (fix it) or a deliberate rendering
  difference (record it in the corpus entry as an allowed alternate — never
  silently regenerate expectations from our own output, which would make the
  test circular).

## 5.2 Similarity: labeled pairs from the fixture matrix

The similarity component is currently **unfalsifiable** — two tests, no
ground truth. The fixture matrix *is* ground truth we already build:

* **Positive pairs:** the same source function across
  `{gcc,clang} × {O0,O2}`, across the arch lanes, and across the stripped
  variants — same semantics, different bytes. That is thousands of labeled
  pairs for free.
* **Negative pairs:** distinct functions sampled from the same builds
  (control for size so the task is not trivially solved by length).
* Test: retrieval framing — for each O0 function, rank all O2 functions in
  the same binary; assert top-1 accuracy ≥ a measured baseline, recorded like
  the other ratchets (measure first, then pin; do not guess a threshold).
  Add a `slow`-marked cross-compiler and cross-arch tier where the honest
  numbers will be lower — pin whatever they are, so regressions show.

## 5.3 FLIRT: signatures from a real static library

* Build a `.sig` from a real `libc.a`/`libstdc++.a` out of the fixture
  Docker image (pinned versions, hermetic), commit the generated signature
  file with its generation script.
* Link one fixture statically in the harness, run FLIRT over it, assert the
  known library functions are identified **and** that fixture-local functions
  are not (the false-positive direction is the one that poisons a KB, given
  `set_by` provenance lets `flirt` outrank `auto`).
* This also gives the KB provenance rules their first integration test:
  FLIRT-named then manually renamed must stay manual.

## 5.4 Target: table-driven spec exhaustion

One test across four files. Cheapest fix in the plan: a table-driven test
enumerating every triple/arch/OS spec the module exposes and asserting the
derived properties (pointer width, endianness, calling convention defaults)
against a hand-written expectation table. An hour of typing; it exists so a
new target edit cannot silently flip an existing one.

## Acceptance

* Each module ≥100 corpus-driven cases in the default suite (demangle ≥5,000).
* Similarity has a pinned, measured retrieval ratchet.
* FLIRT has both a match and a no-false-positive assertion over a real
  static-linked binary.

## Effort

Demangle two days (the triage of oracle divergences is the real work — and
the point). Similarity two days including measuring honest baselines.
FLIRT one day. Target half a day. All four are independent and
agent-delegable in parallel.
