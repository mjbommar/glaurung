"""Retro-score the production structural fingerprint under the identity protocol.

`python/glaurung/llm/kb/structural_fingerprint.py` is the fingerprint
`glaurung diff` ships: normalized instruction tokens per basic block, hashed,
combined with the CFG edge set, plus a multiset-Jaccard "near-miss" score.
It has never been measured as a *retrieval* engine -- only as an equality
oracle for consecutive patch builds of one binary, which is the easiest
regime there is (zero free compilation variables).

This file scores it under the same protocol as the Rust harness in
`tests/identity_retrieval/`: the matched-build fixture corpus, the published
ground-truth filters, Marcelli's XO / XC / XM tasks and size strata, 100
negatives per positive from a fixed-seed SplitMix64 stream, pessimistic tie
handling, and every number printed with its pool size and its free-variable
set. See `docs/development/identity-measurement.md`.

**The task list is reimplemented here, not imported from the Rust run.**
The Rust harness emits `target/identity-eval/ctph.json`, but reusing its
*sample* list would not save this file any work: `structural_fingerprint`
takes a `Function` object, so the Python side has to run its own CFG
discovery whatever the task list says, and a JSON handshake between a
`cargo test` and a `pytest` run would make each one's result depend on
whether the other had been run recently. The rules are duplicated instead,
and `test_python_and_rust_harnesses_agree_on_the_corpus` cross-checks the
two populations whenever the Rust report happens to be present.

Two deliberate differences from the Rust lane, both of which change the
denominator and are therefore stated rather than smoothed over:

1.  **Discovery is unseeded.** The Rust lane seeds `analyze_functions_bytes`
    with the symbol VAs; the Python binding surface exposes no seeded entry
    point, so this lane takes `analyze_functions_path` and reads names off
    whatever discovery found. Different seeds can mean different bodies.

2.  **No `.text` section filter.** Nothing in the binding surface reports a
    function's section. The Rust lane measured that filter removing **zero**
    functions on this corpus, so the omission costs nothing here; on a
    linked multi-object binary it would.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple

import pytest

if TYPE_CHECKING:
    # Type-only: the runtime imports are inside the functions that need them,
    # so collecting this file costs nothing when the corpus is absent.
    from glaurung.llm.kb.structural_fingerprint import FunctionStructure

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parent.parent.parent

# --- protocol constants, mirroring tests/identity_retrieval/ -----------------

#: Marcelli et al. and TikNib both discard functions with fewer than 5 basic
#: blocks. Must equal `corpus::MIN_BASIC_BLOCKS` in the Rust harness.
MIN_BASIC_BLOCKS = 5

#: 100 negatives per positive, so the ranked pool is 101 and chance R@1 is
#: 1/101. Must equal `metrics::NEGATIVES_PER_POSITIVE`.
NEGATIVES_PER_POSITIVE = 100

#: Recall@k rungs. Must equal `metrics::RECALL_KS`.
RECALL_KS = (1, 5, 10, 50)

#: Below this many scored queries a row is reported but must not be quoted.
#: Must equal `metrics::MIN_SCORED_FOR_A_MEASUREMENT`.
MIN_SCORED_FOR_A_MEASUREMENT = 30

#: SplitMix64 seed. Must equal `metrics::NEGATIVE_SAMPLING_SEED`. The stream
#: itself is pinned in `test_splitmix64_matches_the_rust_harness`, because two
#: harnesses that agree on the seed and disagree on the generator draw
#: different negatives while looking identical in every log line.
NEGATIVE_SAMPLING_SEED = 0x9E3779B97F4A7C15

_MASK64 = (1 << 64) - 1

#: CRT boilerplate. Must equal `corpus::CRT_SYMBOLS`.
CRT_SYMBOLS = frozenset(
    {
        "_init",
        "_fini",
        "_start",
        "frame_dummy",
        "register_tm_clones",
        "deregister_tm_clones",
        "__do_global_dtors_aux",
        "__libc_csu_init",
        "__libc_csu_fini",
        "call_weak_fn",
    }
)

COMPILERS = ("gcc", "clang")
OPT_LEVELS = ("O0", "O2")

#: `(name, query slice, pool slice, free variables, stratum)`.
#: Must equal `tasks::TASKS`.
TASKS: Tuple[Tuple[str, Tuple[str, str], Tuple[str, str], str, Optional[str]], ...] = (
    ("XO-gcc", ("gcc", "O0"), ("gcc", "O2"), "optimisation", None),
    ("XO-clang", ("clang", "O0"), ("clang", "O2"), "optimisation", None),
    ("XC-O0", ("gcc", "O0"), ("clang", "O0"), "compiler", None),
    ("XC-O2", ("gcc", "O2"), ("clang", "O2"), "compiler", None),
    ("XM", ("gcc", "O0"), ("clang", "O2"), "compiler + optimisation", None),
    ("XM-S", ("gcc", "O0"), ("clang", "O2"), "compiler + optimisation", "S"),
    ("XM-M", ("gcc", "O0"), ("clang", "O2"), "compiler + optimisation", "M"),
    ("XM-L", ("gcc", "O0"), ("clang", "O2"), "compiler + optimisation", "L"),
)

# --- measured ratchets ------------------------------------------------------
#
# Every constant below was read off a run before it was written down. A number
# may only tighten; drifting more than RATCHET_SLACK above its floor fails too,
# because a ratchet that has fallen behind reality has stopped reporting
# regressions. See the same discipline in `tests/similarity_retrieval.rs` and
# `tests/identity_retrieval/main.rs`.

RATCHET_SLACK = 0.05

#: XO (gcc O0 -> gcc O2) AUC over 389 positives and 38,900 sampled negatives,
#: pool 409.
#:
#: **Measured: 0.582457.** Real signal -- CTPH scores 0.5015 on the same task
#: and the same filtered population -- but the ranking is still poor: R@1 is
#: 0.0257 against a chance of 0.0099, and MRR10 0.0670. The token
#: normalization survives register reallocation; it does not survive what -O2
#: does to the block structure.
FP_XO_GCC_MIN_AUC = 0.582457

#: XO (gcc O0 -> gcc O2) Recall@1 against 100 sampled negatives.
#:
#: **Measured: 0.025707 (10 of 389)**, chance 0.0099.
FP_XO_GCC_MIN_RECALL_AT_1 = 0.025706

#: XC-O2 (gcc O2 -> clang O2) AUC: compiler free, optimisation fixed.
#:
#: **Measured: 0.728691** over 356 positives, pool 379, with R@1 0.1573 and
#: MRR10 0.2241. This is the headline result of the retro-score and it
#: reverses the intuition the corpus was built with: swapping COMPILERS at a
#: fixed optimisation level is far easier for this fingerprint (AUC 0.73) than
#: swapping OPTIMISATION LEVELS with the compiler fixed (0.58). MRR10 0.22
#: puts it right at the FunctionSimSearch band the protocol document names as
#: this representation class's published ceiling (0.26), which is a useful
#: independent check that the harness is measuring what it claims to.
FP_XC_O2_MIN_AUC = 0.728691

#: XM (gcc O0 -> clang O2) AUC: both variables free.
#:
#: **Measured: 0.515014.** Near chance. Every bit of the cross-compiler
#: strength above is destroyed by adding the optimisation level, which is
#: exactly the collapse-with-multiple-free-variables the protocol document
#: reports for token-level representations.
FP_XM_MIN_AUC = 0.515013

#: XM Recall@1 against the whole clang O2 pool of 379.
#:
#: **Measured: 0.010989 (4 of 364)**, chance 0.002639.
FP_XM_MIN_GLOBAL_RECALL_AT_1 = 0.010988

#: Ceiling on the mean fingerprint cost, milliseconds per function.
#:
#: **Measured: 25.5 ms/function over 1,786 samples**, against TikNib's
#: 0.02-1.03 ms -- twenty-five times the top of the published band. The cost
#: is structural, not incidental: `structural_fingerprint` takes its slow path
#: on ELF (`build_va_table` is PE-only and returns `[]`, so `fast_path` is
#: False) and calls `disassemble_window_at(path, ...)` **per basic block**,
#: which re-reads the file off disk every time.
#:
#: A ceiling rather than a ratchet: it is wall clock on a shared developer
#: machine, where a tight floor would fail for reasons unrelated to the code.
FP_MAX_EXTRACTION_MS = 200.0


# --- corpus -----------------------------------------------------------------


def corpus_root() -> Optional[Path]:
    """Resolve the matched-build corpus, or ``None``.

    `GLAURUNG_IDENTITY_CORPUS` first, then the manifest-relative
    `tests/decompiler_fixtures/build`. The directory is gitignored and built
    by the fixture harness, so a fresh checkout legitimately has none; the
    caller must SKIP LOUDLY rather than pass vacuously.

    This env var is read from `python/tests/`, not from `src/`, so it is
    outside the allowlist `test_src_dependency_boundaries.py` enforces over
    the product tree. It is documented in
    `docs/development/identity-measurement.md`.
    """
    env = os.environ.get("GLAURUNG_IDENTITY_CORPUS")
    candidates = [Path(env)] if env else []
    candidates.append(ROOT / "tests" / "decompiler_fixtures" / "build")
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.iterdir()):
            return candidate
    return None


@dataclass(frozen=True)
class Sample:
    """One labelled function and its production fingerprint."""

    fixture: str
    name: str
    compiler: str
    opt: str
    block_count: int
    structure: "FunctionStructure"

    @property
    def label(self) -> Tuple[str, str]:
        return (self.fixture, self.name)


@dataclass
class FilterCounts:
    """What each published filter removed. Printed with every result."""

    considered: int = 0
    dropped_plt_or_thunk: int = 0
    dropped_small: int = 0
    dropped_no_fingerprint: int = 0
    dropped_duplicate: int = 0
    kept: int = 0

    def add(self, other: "FilterCounts") -> None:
        self.considered += other.considered
        self.dropped_plt_or_thunk += other.dropped_plt_or_thunk
        self.dropped_small += other.dropped_small
        self.dropped_no_fingerprint += other.dropped_no_fingerprint
        self.dropped_duplicate += other.dropped_duplicate
        self.kept += other.kept

    def summary(self) -> str:
        return (
            f"considered {self.considered} -> kept {self.kept} "
            f"(dropped: plt/thunk/crt {self.dropped_plt_or_thunk}, "
            f"<{MIN_BASIC_BLOCKS} blocks {self.dropped_small}, "
            f"no-fingerprint {self.dropped_no_fingerprint}, "
            f"duplicate {self.dropped_duplicate})"
        )


def is_plt_or_thunk(name: str) -> bool:
    """PLT entries, thunks and CRT boilerplate. Mirrors `corpus::is_plt_or_thunk`.

    On this corpus it removes nothing -- these are single-translation-unit
    shared objects whose symbol tables carry no ``@plt`` names -- which is why
    `test_filter_predicates_match_the_rust_harness` tests it directly instead
    of trusting the corpus count.
    """
    if "@plt" in name:
        return True
    if name in CRT_SYMBOLS:
        return True
    return name.startswith("__x86.get_pc_thunk") or name.startswith("__tls_get_addr")


def _load_image(
    path: Path, fixture: str, compiler: str, opt: str
) -> Tuple[List[Sample], FilterCounts, float]:
    """Discover, fingerprint and filter one image. Returns samples, counts, seconds."""
    import glaurung as g
    from glaurung.llm.kb.structural_fingerprint import structural_fingerprint

    counts = FilterCounts()
    try:
        functions, _cg = g.analysis.analyze_functions_path(str(path))
    except Exception:
        return [], counts, 0.0

    out: List[Sample] = []
    spent = 0.0
    # Sorted by name so the per-image order is fixed regardless of discovery
    # order; the slice is sorted again by (fixture, name) afterwards.
    for func in sorted(
        functions, key=lambda f: (str(f.name), int(f.entry_point.value))
    ):
        name = str(func.name)
        if not name:
            continue
        counts.considered += 1
        if is_plt_or_thunk(name):
            counts.dropped_plt_or_thunk += 1
            continue
        blocks = list(func.basic_blocks or [])
        if len(blocks) < MIN_BASIC_BLOCKS:
            counts.dropped_small += 1
            continue
        started = time.perf_counter()
        structure = structural_fingerprint(func=func, path=str(path), iat_by_va={})
        spent += time.perf_counter() - started
        if structure is None:
            counts.dropped_no_fingerprint += 1
            continue
        counts.kept += 1
        out.append(
            Sample(
                fixture=fixture,
                name=name,
                compiler=compiler,
                opt=opt,
                block_count=len(blocks),
                structure=structure,
            )
        )
    return out, counts, spent


def _load_slice(
    root: Path, compiler: str, opt: str
) -> Tuple[List[Sample], FilterCounts, float]:
    """One `(compiler, opt)` slice, filtered, deduped and sorted."""
    suffix = f"-{compiler}-{opt}.so"
    images = sorted(
        (p.name[: -len(suffix)], p)
        for p in root.iterdir()
        if p.name.endswith(suffix) and not p.name[: -len(suffix)].endswith(".dwarf")
    )

    filters = FilterCounts()
    samples: List[Sample] = []
    spent = 0.0
    # Dedupe by (name, normalized instruction hash), the published rule. Here
    # the normalized instruction hash is the structural fingerprint itself:
    # it IS a hash of normalized instruction tokens plus the CFG, which is
    # exactly what the rule asks for on this side.
    seen: set = set()
    for fixture, path in images:
        image_samples, counts, image_seconds = _load_image(path, fixture, compiler, opt)
        filters.add(counts)
        spent += image_seconds
        for sample in image_samples:
            key = (sample.name, sample.structure.fingerprint)
            if key in seen:
                filters.dropped_duplicate += 1
                filters.kept -= 1
                continue
            seen.add(key)
            samples.append(sample)
    samples.sort(key=lambda s: (s.fixture, s.name))
    return samples, filters, spent


_CORPUS_CACHE: Optional[
    Tuple[Dict[Tuple[str, str], List[Sample]], FilterCounts, float, float]
] = None


def load_corpus() -> Optional[
    Tuple[Dict[Tuple[str, str], List[Sample]], FilterCounts, float, float]
]:
    """Load every slice once per session. Returns slices, filters, load s, extract s."""
    global _CORPUS_CACHE
    if _CORPUS_CACHE is not None:
        return _CORPUS_CACHE
    root = corpus_root()
    if root is None:
        return None
    started = time.perf_counter()
    slices: Dict[Tuple[str, str], List[Sample]] = {}
    filters = FilterCounts()
    extract_seconds = 0.0
    for compiler in COMPILERS:
        for opt in OPT_LEVELS:
            samples, counts, spent = _load_slice(root, compiler, opt)
            filters.add(counts)
            extract_seconds += spent
            slices[(compiler, opt)] = samples
    _CORPUS_CACHE = (slices, filters, time.perf_counter() - started, extract_seconds)
    return _CORPUS_CACHE


def require_corpus():
    """Load the corpus or skip with the reason spelled out."""
    loaded = load_corpus()
    if loaded is None:
        pytest.skip(
            "no identity corpus: tests/decompiler_fixtures/build/ is empty and "
            "GLAURUNG_IDENTITY_CORPUS is unset or does not point at a populated "
            "build directory. It is gitignored and built by the fixture harness "
            "(docs/development/decompiler-testing.md). Protocol: "
            "docs/development/identity-measurement.md."
        )
    return loaded


# --- metrics ----------------------------------------------------------------


def splitmix64(state: int) -> Tuple[int, int]:
    """One step of SplitMix64. Returns ``(new_state, value)``.

    Byte-for-byte the generator in `metrics.rs`, so the two harnesses draw the
    same negatives for the same `(task, query index)`.
    """
    state = (state + 0x9E3779B97F4A7C15) & _MASK64
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & _MASK64
    return state, z ^ (z >> 31)


def fnv1a(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & _MASK64
    return h


def sample_negatives(
    task_name: str, query_index: int, query: Sample, pool: Sequence[Sample]
) -> List[int]:
    """Draw up to `NEGATIVES_PER_POSITIVE` distinct non-twin pool indices.

    Deterministic and pool-order independent, and every negative comes from
    the task's own pool slice -- so a cross-optimisation negative necessarily
    shares the compiler, which is the discipline Marcelli names as a frequent
    silent source of inflated published results.
    """
    eligible = [i for i, cand in enumerate(pool) if cand.label != query.label]
    if len(eligible) <= NEGATIVES_PER_POSITIVE:
        return eligible
    state = (
        NEGATIVE_SAMPLING_SEED
        ^ fnv1a(task_name.encode())
        ^ ((query_index * 0x2545F4914F6CDD1D) & _MASK64)
    ) & _MASK64
    chosen: set = set()
    draws = 0
    while len(chosen) < NEGATIVES_PER_POSITIVE and draws < NEGATIVES_PER_POSITIVE * 64:
        state, value = splitmix64(state)
        chosen.add(eligible[value % len(eligible)])
        draws += 1
    return sorted(chosen)


def auc(positives: Sequence[float], negatives: Sequence[float]) -> float:
    """Mann-Whitney U with mid-ranks for ties. Mirrors `metrics::auc`."""
    if not positives or not negatives:
        return 0.0
    entries = sorted(
        [(s, True) for s in positives] + [(s, False) for s in negatives],
        key=lambda e: e[0],
    )
    rank_sum = 0.0
    i = 0
    while i < len(entries):
        j = i
        while j + 1 < len(entries) and entries[j + 1][0] == entries[i][0]:
            j += 1
        mid = (i + j) / 2.0 + 1.0
        for entry in entries[i : j + 1]:
            if entry[1]:
                rank_sum += mid
        i = j + 1
    n_pos, n_neg = len(positives), len(negatives)
    return (rank_sum - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def recall_at(ranks: Sequence[int], k: int) -> float:
    if not ranks:
        return 0.0
    return sum(1 for r in ranks if r <= k) / len(ranks)


def mrr(ranks: Sequence[int], cutoff: int = 10) -> float:
    if not ranks:
        return 0.0
    return sum((1.0 / r) if r <= cutoff else 0.0 for r in ranks) / len(ranks)


def in_stratum(sample: Sample, stratum: Optional[str]) -> bool:
    """XM-S (<20 blocks), XM-M (20-100), XM-L (>100). Mirrors `tasks::Stratum`."""
    if stratum is None:
        return True
    n = sample.block_count
    if stratum == "S":
        return n < 20
    if stratum == "M":
        return 20 <= n <= 100
    return n > 100


@dataclass
class TaskResult:
    """One task's measurement. Pool sizes and free variables are not optional."""

    task_name: str
    conditions: str
    queries_in_scope: int
    scored: int
    global_pool_size: int
    sampled_pool_size: int
    auc: float
    mrr10: float
    recall_at_k: Dict[int, float]
    global_recall_at_1: float
    mean_positive_score: float
    mean_negative_score: float

    @property
    def underpowered(self) -> bool:
        return self.scored < MIN_SCORED_FOR_A_MEASUREMENT

    def line(self) -> str:
        recalls = " ".join(f"R@{k} {self.recall_at_k[k]:.4f}" for k in RECALL_KS)
        flag = " [UNDERPOWERED]" if self.underpowered else ""
        return (
            f"{self.task_name:<8}{flag} {self.conditions} | "
            f"scored {self.scored}/{self.queries_in_scope} | "
            f"pool {self.sampled_pool_size} (+{self.global_pool_size} global) | "
            f"AUC {self.auc:.4f} MRR10 {self.mrr10:.4f} {recalls} | "
            f"global R@1 {self.global_recall_at_1:.4f} "
            f"(chance {1.0 / max(self.global_pool_size, 1):.4f}) | "
            f"mean pos {self.mean_positive_score:.4f} neg {self.mean_negative_score:.4f}"
        )

    def to_json(self) -> dict:
        return {
            "task": self.task_name,
            "conditions": self.conditions,
            "queries_in_scope": self.queries_in_scope,
            "scored": self.scored,
            "underpowered": self.underpowered,
            "sampled_pool_size": self.sampled_pool_size,
            "global_pool_size": self.global_pool_size,
            "auc": self.auc,
            "mrr10": self.mrr10,
            "recall_at_k": {str(k): v for k, v in sorted(self.recall_at_k.items())},
            "global_recall_at_1": self.global_recall_at_1,
            "sampled_chance_recall_at_1": 1.0 / self.sampled_pool_size,
            "global_chance_recall_at_1": 1.0 / max(self.global_pool_size, 1),
            "mean_positive_score": self.mean_positive_score,
            "mean_negative_score": self.mean_negative_score,
        }


def evaluate_task(
    task_name: str,
    queries: Sequence[Sample],
    pool: Sequence[Sample],
    free_variables: str,
    stratum: Optional[str],
    query_slice: Tuple[str, str],
    pool_slice: Tuple[str, str],
) -> TaskResult:
    """Score one task. Ties are pessimistic: a tied candidate ranks AHEAD."""
    from glaurung.llm.kb.structural_fingerprint import similarity_score

    by_label = {s.label: i for i, s in enumerate(pool)}
    in_scope = [q for q in queries if in_stratum(q, stratum)]

    positives: List[float] = []
    negatives: List[float] = []
    sampled_ranks: List[int] = []
    global_ranks: List[int] = []

    for query_index, query in enumerate(in_scope):
        twin_index = by_label.get(query.label)
        if twin_index is None:
            # Inlined away in the other build: no right answer exists, and
            # counting it as a miss would measure the compiler, not us.
            continue
        positive = similarity_score(query.structure, pool[twin_index].structure)
        positives.append(positive)

        ahead = 0
        for neg_index in sample_negatives(task_name, query_index, query, pool):
            score = similarity_score(query.structure, pool[neg_index].structure)
            negatives.append(score)
            if score >= positive:
                ahead += 1
        sampled_ranks.append(ahead + 1)

        global_ahead = 0
        for cand_index, cand in enumerate(pool):
            if cand_index == twin_index:
                continue
            if similarity_score(query.structure, cand.structure) >= positive:
                global_ahead += 1
        global_ranks.append(global_ahead + 1)

    conditions = (
        f"{query_slice[0]}/{query_slice[1]} -> {pool_slice[0]}/{pool_slice[1]} "
        f"(free: {free_variables})"
    )
    if stratum is not None:
        conditions += f", queries {'<20 blocks' if stratum == 'S' else '20-100 blocks' if stratum == 'M' else '>100 blocks'}"

    mean = lambda v: (sum(v) / len(v)) if v else 0.0  # noqa: E731
    return TaskResult(
        task_name=task_name,
        conditions=conditions,
        queries_in_scope=len(in_scope),
        scored=len(sampled_ranks),
        global_pool_size=len(pool),
        sampled_pool_size=NEGATIVES_PER_POSITIVE + 1,
        auc=auc(positives, negatives),
        mrr10=mrr(sampled_ranks),
        recall_at_k={k: recall_at(sampled_ranks, k) for k in RECALL_KS},
        global_recall_at_1=recall_at(global_ranks, 1),
        mean_positive_score=mean(positives),
        mean_negative_score=mean(negatives),
    )


_REPORT_CACHE: Optional[Tuple[Dict[str, TaskResult], float]] = None


def scheme_report() -> Tuple[Dict[str, TaskResult], float]:
    """Score every task once per session, write the JSON report.

    Returns ``(results by task name, mean fingerprint milliseconds/function)``.
    """
    global _REPORT_CACHE
    if _REPORT_CACHE is not None:
        return _REPORT_CACHE
    slices, filters, load_seconds, extract_seconds = require_corpus()

    results: Dict[str, TaskResult] = {}
    for name, query_slice, pool_slice, free_variables, stratum in TASKS:
        results[name] = evaluate_task(
            name,
            slices[query_slice],
            slices[pool_slice],
            free_variables,
            stratum,
            query_slice,
            pool_slice,
        )

    total_kept = sum(len(v) for v in slices.values())
    extraction_ms = (extract_seconds * 1000.0 / total_kept) if total_kept else 0.0
    print(f"\ncorpus: {filters.summary()} in {load_seconds:.1f}s")
    for key in sorted(slices):
        print(f"  {key[0]}/{key[1]}: {len(slices[key])} functions")
    print(f"extraction {extraction_ms:.2f} ms/function over {total_kept} samples")
    for name, _, _, _, _ in TASKS:
        print(results[name].line())

    report_dir = (
        Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "identity-eval"
    )
    try:
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "python-structural-fingerprint.json").write_text(
            json.dumps(
                {
                    "scheme": "python-structural-fingerprint",
                    "description": (
                        "python/glaurung/llm/kb/structural_fingerprint.py: normalized "
                        "instruction tokens per block + CFG edge set; multiset-Jaccard "
                        "over block token hashes"
                    ),
                    "protocol": "docs/development/identity-measurement.md",
                    "corpus_filters": {
                        "considered": filters.considered,
                        "dropped_plt_or_thunk": filters.dropped_plt_or_thunk,
                        "dropped_under_min_blocks": filters.dropped_small,
                        "dropped_no_fingerprint": filters.dropped_no_fingerprint,
                        "dropped_duplicate": filters.dropped_duplicate,
                        "kept": filters.kept,
                        "min_basic_blocks": MIN_BASIC_BLOCKS,
                    },
                    "corpus_slices": [
                        {"compiler": c, "opt": o, "kept": len(slices[(c, o)])}
                        for (c, o) in sorted(slices)
                    ],
                    "negatives_per_positive": NEGATIVES_PER_POSITIVE,
                    "negative_sampling_prng": "SplitMix64",
                    "negative_sampling_seed": NEGATIVE_SAMPLING_SEED,
                    "tie_handling": "pessimistic: a candidate tied with the twin ranks ahead of it",
                    "extraction_ms_per_function": extraction_ms,
                    "extraction_samples": total_kept,
                    "tasks": [results[name].to_json() for name, *_ in TASKS],
                },
                indent=2,
            )
        )
        print(f"report: {report_dir / 'python-structural-fingerprint.json'}")
    except OSError as e:  # pragma: no cover - reporting must not fail a run
        print(f"could not write the JSON report: {e}")

    _REPORT_CACHE = (results, extraction_ms)
    return _REPORT_CACHE


# --- tests ------------------------------------------------------------------


def test_splitmix64_matches_the_rust_harness():
    """The two harnesses must draw the same negatives, not merely claim to.

    Pinned against the same four values `metrics::tests::splitmix64_stream_is_fixed`
    pins. A Python generator that agreed on the seed and disagreed on the
    mixing constants would produce a different negative sample and a
    different, uncomparable set of numbers, with nothing in either log to say
    so. Runs without the corpus.
    """
    state = NEGATIVE_SAMPLING_SEED
    values = []
    for _ in range(4):
        state, value = splitmix64(state)
        values.append(value)
    assert values == [
        0x6E789E6AA1B965F4,
        0x06C45D188009454F,
        0xF88BB8A8724C81EC,
        0x1B39896A51A8749B,
    ]


def test_filter_predicates_match_the_rust_harness():
    """The PLT/CRT rule, tested directly.

    It removes zero functions on this corpus, so the corpus counts can never
    tell a working filter from one that returns ``False`` unconditionally.
    Same reasoning and same cases as
    `corpus::tests::plt_and_crt_names_are_recognised`. Runs without the corpus.
    """
    assert is_plt_or_thunk("memcpy@plt")
    assert is_plt_or_thunk("frame_dummy")
    assert is_plt_or_thunk("_init")
    assert is_plt_or_thunk("__x86.get_pc_thunk.bx")
    assert not is_plt_or_thunk("bisect")
    assert not is_plt_or_thunk("checksum")
    assert not is_plt_or_thunk("my_init")
    assert not is_plt_or_thunk("_initialise")


def test_metric_helpers_agree_with_their_definitions():
    """AUC endpoints, Recall@k and MRR10. Mirrors `metrics::tests`.

    Without this the statistics could be off by a constant and every reported
    number would move together -- an error a corpus measurement cannot detect
    on its own. Runs without the corpus.
    """
    assert auc([1.0, 0.9], [0.1, 0.2]) == 1.0
    assert auc([0.1, 0.2], [1.0, 0.9]) == 0.0
    assert auc([0.5, 0.5], [0.5, 0.5]) == 0.5
    assert auc([0.5], [0.4, 0.5]) == 0.75

    ranks = [1, 2, 11, 4]
    assert recall_at(ranks, 1) == 0.25
    assert recall_at(ranks, 5) == 0.75
    assert recall_at(ranks, 50) == 1.0
    assert abs(mrr(ranks) - (1.0 + 0.5 + 0.0 + 0.25) / 4.0) < 1e-12


def test_corpus_loads_with_the_published_filters_applied():
    """The population every number below is computed on."""
    _slices, filters, _load_s, _extract_s = require_corpus()
    assert filters.considered >= 2000, filters.summary()
    assert filters.dropped_small > 0, (
        f"the <{MIN_BASIC_BLOCKS}-block filter removed nothing: {filters.summary()}"
    )
    assert filters.kept >= 400, filters.summary()


def test_structural_fingerprint_obeys_the_similarity_axioms():
    """Identity on the quotient, symmetry, and range.

    The metric axioms the protocol document asks to ship with the first hash.
    They hold for a scheme that is otherwise useless, which is why they are
    separate from the retrieval numbers rather than folded into them.
    """
    from glaurung.llm.kb.structural_fingerprint import similarity_score

    slices, _filters, _load_s, _extract_s = require_corpus()
    samples = slices[("gcc", "O0")]
    assert len(samples) >= 80

    for i, a in enumerate(samples):
        assert abs(similarity_score(a.structure, a.structure) - 1.0) < 1e-9, (
            f"{a.fixture}::{a.name} does not match itself"
        )
        if i + 1 < len(samples):
            b = samples[i + 1]
            ab = similarity_score(a.structure, b.structure)
            ba = similarity_score(b.structure, a.structure)
            assert abs(ab - ba) < 1e-12, f"asymmetric: {a.name} vs {b.name}"
            assert 0.0 <= ab <= 1.0, f"score {ab} outside [0, 1]"


def test_ground_truth_join_and_negative_pool_are_sound():
    """A real join, a pool big enough for the sampled metrics to be honest."""
    results, _extraction_ms = scheme_report()
    for name, result in results.items():
        assert result.scored > 0, (
            f"{name}: no query had a twin in the pool. The (fixture, name) join "
            f"is broken, not the scheme. Conditions: {result.conditions}"
        )
        assert result.global_pool_size > NEGATIVES_PER_POSITIVE, (
            f"{name}: pool of {result.global_pool_size} cannot supply "
            f"{NEGATIVES_PER_POSITIVE} distinct negatives, so the reported "
            f"sampled pool size of {result.sampled_pool_size} is a fiction"
        )

    strata = sum(results[n].queries_in_scope for n in ("XM-S", "XM-M", "XM-L"))
    assert strata == results["XM"].queries_in_scope, (
        f"the three size strata hold {strata} queries but XM holds "
        f"{results['XM'].queries_in_scope}; the bands do not partition"
    )


def test_structural_fingerprint_retrieval_ratchets():
    """What the shipped Python fingerprint actually scores under this protocol."""
    results, extraction_ms = scheme_report()

    xo = results["XO-gcc"]
    _assert_ratchet("XO-gcc AUC", xo.auc, FP_XO_GCC_MIN_AUC, xo.line())
    _assert_ratchet(
        "XO-gcc Recall@1", xo.recall_at_k[1], FP_XO_GCC_MIN_RECALL_AT_1, xo.line()
    )

    xc = results["XC-O2"]
    _assert_ratchet("XC-O2 AUC", xc.auc, FP_XC_O2_MIN_AUC, xc.line())

    xm = results["XM"]
    _assert_ratchet("XM AUC", xm.auc, FP_XM_MIN_AUC, xm.line())
    _assert_ratchet(
        "XM global Recall@1",
        xm.global_recall_at_1,
        FP_XM_MIN_GLOBAL_RECALL_AT_1,
        xm.line(),
    )

    assert extraction_ms <= FP_MAX_EXTRACTION_MS, (
        f"fingerprint cost {extraction_ms:.2f} ms/function, ceiling "
        f"{FP_MAX_EXTRACTION_MS:.2f}"
    )


def test_python_and_rust_harnesses_agree_on_the_corpus():
    """Cross-check the two populations when the Rust report is present.

    The rules are implemented twice, in two languages, and two harnesses that
    quietly filter different populations produce two uncomparable sets of
    numbers while both look correct. This is the check that would notice.
    Skips when `cargo test --test identity_retrieval` has not been run.
    """
    report_path = (
        Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
        / "identity-eval"
        / "ctph.json"
    )
    if not report_path.is_file():
        pytest.skip(
            f"{report_path} absent: run `cargo test --features python-ext "
            f"--test identity_retrieval` first to produce it"
        )
    rust = json.loads(report_path.read_text())
    assert rust["negatives_per_positive"] == NEGATIVES_PER_POSITIVE
    assert rust["negative_sampling_seed"] == NEGATIVE_SAMPLING_SEED
    assert rust["corpus_filters"]["min_basic_blocks"] == MIN_BASIC_BLOCKS
    assert rust["min_scored_for_a_measurement"] == MIN_SCORED_FOR_A_MEASUREMENT

    slices, _filters, _load_s, _extract_s = require_corpus()
    rust_slices = {(s["compiler"], s["opt"]): s["kept"] for s in rust["corpus_slices"]}
    for key, samples in slices.items():
        rust_kept = rust_slices.get(key)
        assert rust_kept is not None, f"the Rust report has no {key} slice"
        # Not equality: the Rust lane seeds discovery with symbol VAs and the
        # Python binding surface has no seeded entry point, so the two
        # populations legitimately differ a little. A large gap means one of
        # them is filtering something the other is not.
        ratio = len(samples) / rust_kept
        assert 0.75 <= ratio <= 1.25, (
            f"{key}: Python kept {len(samples)}, Rust kept {rust_kept} "
            f"(ratio {ratio:.2f}). The two harnesses are measuring different "
            f"populations, so their numbers are not comparable."
        )

    rust_tasks = {t["task"] for t in rust["tasks"]}
    assert rust_tasks == {name for name, *_ in TASKS}, (
        "the task lists have drifted apart"
    )


def _assert_ratchet(what: str, measured: float, floor: float, context: str) -> None:
    """Assert a measured number against its floor, in both directions."""
    print(f"{what}: {measured:.6f} (ratchet {floor:.6f})")
    assert measured >= floor, (
        f"{what} fell to {measured:.6f}, ratchet {floor:.6f}.\n{context}"
    )
    assert measured <= floor + RATCHET_SLACK, (
        f"{what} improved to {measured:.6f}, more than {RATCHET_SLACK:.2f} above "
        f"the ratchet {floor:.6f} -- good news. Raise the constant in "
        f"python/tests/test_identity_retrieval_protocol.py in the same commit, "
        f"or the improvement is unprotected.\n{context}"
    )
