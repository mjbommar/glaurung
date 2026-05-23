"""CWE-class-driven discovery sweep (L3).

A single open-ended "find any bug" prompt drifts into compiler-runtime
helpers and over-asserts. The sweep replaces it with a small catalog of
focused per-CWE prompts; each runs as its own structured-output
:class:`FindingsReport` pass, and the per-class reports merge into one.

Per-class entry shape::

    {
        "id": "CWE-121",
        "title": "Stack-based Buffer Overflow",
        "prompt": "...",        # what to send to the agent
        "applies_to": "userland" | "kernel" | "any",
    }

Each prompt is short and instruction-dense: tell the agent exactly the
shape we want it to look for, not a generic 'find bugs'. The L2 critic
and L4 verifier still run per finding regardless of which class
surfaced it -- the merged report is fully validated before the user
sees it.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

from .findings import FindingsReport
from .findings_runner import run_findings_pass


logger = logging.getLogger(__name__)


@dataclass
class CWEClassSpec:
    id: str
    title: str
    prompt: str
    applies_to: str = "any"  # 'userland', 'kernel', or 'any'


# Initial catalog -- mirror the corpus we built in this session, plus
# the kernel-IRP shape that the v2 cwe476 driver exercises. Extending
# the catalog is the canonical way to widen the sweep's coverage; each
# entry should be a SHAPE the rule layer doesn't already model.
DEFAULT_CWE_CLASSES: list[CWEClassSpec] = [
    CWEClassSpec(
        id="CWE-121",
        title="Stack-based buffer overflow",
        prompt=(
            "Find unbounded copies into a fixed-size stack buffer. "
            "Concretely: callsites of strcpy, strcat, sprintf, vsprintf, "
            "gets, lstrcpy*, lstrcat*, where the destination expression "
            "references a stack slot (rsp+0xN, rbp-0xN, or a local "
            "decompiled as stack_X), and the source is caller-derived "
            "(argv, fgets'd line, caller_arg). "
            "Also flag strncpy / snprintf when the length argument is "
            "itself caller-derived. Do NOT flag bounded copies whose "
            "length is a literal that matches the destination's known size."
        ),
        applies_to="any",
    ),
    CWEClassSpec(
        id="CWE-134",
        title="Externally-controlled format string",
        prompt=(
            "Find printf-family callsites whose first argument is NOT a "
            "string literal -- i.e. the format string is caller-derived. "
            "Look at printf, fprintf, sprintf, vsprintf, vprintf, "
            "snprintf, and any inlined __mingw_printf wrapper. The "
            "decompile signal is a `printf(x)` call where `x` resolves to "
            "a caller_arg or a global string buffer the user can write. "
            "Confirm by checking that there's no companion literal "
            "format string and that the argument count to printf is 1."
        ),
        applies_to="any",
    ),
    CWEClassSpec(
        id="CWE-190",
        title="Integer overflow before allocation",
        prompt=(
            "Find arithmetic on caller-derived values used as the size "
            "argument to an allocator (malloc, calloc, realloc, "
            "HeapAlloc, VirtualAlloc, new). Concretely: a multiplication "
            "or addition where at least one operand resolves to "
            "caller_arg, with no preceding saturating helper "
            "(SizeTMult, RtlULongLongToULong, checked_mul, manual bound "
            "vs SIZE_MAX/UINT_MAX). For calloc, both multiplicands "
            "count. Cite the exact `imul` / `add` instruction and the "
            "subsequent allocator call."
        ),
        applies_to="any",
    ),
    CWEClassSpec(
        id="CWE-416",
        title="Use after free",
        prompt=(
            "Find paths where memory is freed (free, HeapFree, "
            "operator delete) and the SAME pointer is later read or "
            "written -- either in the same function OR via a global "
            "table / registry that wasn't cleared on free. The textbook "
            "shape is `free(p); ...; use *p` or "
            "`registry[i] = HeapAlloc(...); ...; HeapFree(registry[i]); "
            "// registry[i] not cleared`. Cite the free call and the "
            "subsequent use; do NOT confuse with reads that happen "
            "BEFORE the free."
        ),
        applies_to="any",
    ),
    CWEClassSpec(
        id="CWE-401",
        title="Missing release of allocated memory",
        prompt=(
            "Find allocator callsites (malloc/HeapAlloc/...) whose "
            "result is reachable on at least one function exit without "
            "a matching free/HeapFree on that path. Don't flag "
            "intentional ownership transfer to a caller via return "
            "value or out-parameter."
        ),
        applies_to="any",
    ),
    CWEClassSpec(
        id="CWE-476",
        title="NULL or untrusted pointer dereference (kernel IRP)",
        prompt=(
            "Find IRP_MJ_DEVICE_CONTROL dispatcher functions in a "
            "kernel driver that read PIRP->AssociatedIrp.SystemBuffer "
            "(offset 0x18) or PIRP->UserBuffer (offset 0x70) and "
            "dereference the loaded pointer without calling "
            "ProbeForRead or ProbeForWrite anywhere in the function. "
            "The detection signature is: (a) a call to "
            "IofCompleteRequest, (b) a memory load with base=arg1 "
            "and offset=0x18, (c) no ProbeForRead/Write call. Cite "
            "all three pieces."
        ),
        applies_to="kernel",
    ),
    CWEClassSpec(
        id="CWE-787",
        title="Out-of-bounds write",
        prompt=(
            "Find array-index or pointer-arithmetic stores where the "
            "index is caller-derived and the bound check (if any) is "
            "missing or insufficient (e.g. `if (i < N)` but i is "
            "signed and could be negative; or no check at all). Cite "
            "the index computation and the store instruction."
        ),
        applies_to="any",
    ),
]


def _select_classes(
    classes: list[CWEClassSpec],
    applies_to_filter: Optional[str],
) -> list[CWEClassSpec]:
    if not applies_to_filter or applies_to_filter == "any":
        return list(classes)
    out = []
    for c in classes:
        if c.applies_to == "any" or c.applies_to == applies_to_filter:
            out.append(c)
    return out


async def sweep_binary(
    binary_path: str,
    args: Any,
    *,
    classes: Optional[list[CWEClassSpec]] = None,
    applies_to_filter: Optional[str] = None,
    max_parallel: int = 1,
    partial_dir: Optional[str] = None,
) -> FindingsReport:
    """Run a per-CWE-class structured-output pass for each class in
    ``classes`` (defaults to :data:`DEFAULT_CWE_CLASSES`) and merge the
    results into a single ``FindingsReport``.

    ``max_parallel`` caps concurrent LLM calls.

    ``partial_dir`` (F7): when set, each successful class's report is
    written to ``<partial_dir>/<cwe>.partial.json`` immediately after
    that class completes. If the sweep is killed mid-flight (SIGTERM,
    F5 cost-budget abort, unhandled exception), these files survive so
    operators can recover whatever finished. The successful end-of-sweep
    path deletes its own partials before returning.
    """
    classes = classes or DEFAULT_CWE_CLASSES
    classes = _select_classes(classes, applies_to_filter)

    sem = asyncio.Semaphore(max_parallel)

    # F5: import the budget exception so we can re-raise it cleanly
    # without being caught by the generic Exception arm below.
    from .usage_tracker import CostBudgetExceeded
    # F7: partial-dir setup (write per-class JSON immediately).
    from pathlib import Path
    partial_root: Optional[Path] = None
    if partial_dir:
        partial_root = Path(partial_dir)
        partial_root.mkdir(parents=True, exist_ok=True)
    partials_written: list[Path] = []

    def _flush_partial(spec_id: str, rep: FindingsReport) -> None:
        if partial_root is None:
            return
        try:
            safe_id = spec_id.replace("/", "_").replace(":", "_")
            out = partial_root / f"{safe_id}.partial.json"
            out.write_text(rep.model_dump_json(indent=2), encoding="utf-8")
            partials_written.append(out)
        except Exception as e:  # never let partial-write kill the sweep
            logger.warning("partial write for %s failed: %s", spec_id, e)

    async def _one(spec: CWEClassSpec) -> FindingsReport:
        async with sem:
            class_args = _ClassScopedArgs(args, spec)
            try:
                report = await run_findings_pass(binary_path, class_args)
            except CostBudgetExceeded:
                # F5: budget hit. Re-raise so sweep_binary's caller
                # can short-circuit (no further classes fire, partial
                # output is flushed by F7's incremental writes).
                logger.warning(
                    "sweep class %s aborted: cost budget exceeded",
                    spec.id,
                )
                raise
            except Exception as e:
                # Per-class failure (rate limit, validation, etc.) gets
                # recorded as a note but doesn't kill the whole sweep.
                logger.warning(
                    "sweep class %s failed for %s: %s",
                    spec.id, binary_path, e,
                )
                return FindingsReport(
                    binary_path=binary_path,
                    notes=f"[sweep-class-error {spec.id}] {type(e).__name__}: {e}",
                )
            # Force the CWE id onto every emitted finding from this
            # class -- the agent occasionally returns a related id
            # (e.g. CWE-120 for our CWE-121 prompt), and we want
            # cross-class merging to dedup by *requested* class.
            for f in report.findings:
                if not f.cwe.startswith(spec.id):
                    f.alternates.append(
                        type(f)(
                            cwe=f.cwe,
                            cwe_name=f.cwe_name,
                            function=f.function,
                            bug_site=f.bug_site,
                            root_cause=(
                                f"(agent originally classed as {f.cwe}) "
                                + f.root_cause
                            ),
                            evidence=list(f.evidence),
                            confidence=f.confidence,
                        )
                    )
                    f.cwe = spec.id
                    f.cwe_name = spec.title
            # F7: write this class's partial JSON immediately.
            _flush_partial(spec.id, report)
            return report

    # F5: collect class reports as they arrive; if CostBudgetExceeded
    # bubbles up, return what we have so partial findings survive.
    reports: list[FindingsReport] = []
    pending = [_one(spec) for spec in classes]
    try:
        if max_parallel == 1:
            # Sequential -- preserve order and stop at first budget hit.
            for coro in pending:
                reports.append(await coro)
        else:
            reports = list(await asyncio.gather(*pending))
    except CostBudgetExceeded as e:
        logger.warning(
            "sweep aborted mid-flight on %s: %s -- returning partial "
            "findings (%d classes completed)",
            binary_path, e, len(reports),
        )
        merged = FindingsReport.merge(reports)
        existing = merged.notes or ""
        sep = "\n" if existing else ""
        object.__setattr__(
            merged, "notes",
            f"{existing}{sep}[sweep-aborted-cost-budget] {e}",
        )
        return merged

    merged = FindingsReport.merge(reports)
    # F7: successful end-of-sweep cleans up its own partials. If the
    # caller wants them retained for inspection, they should copy the
    # files out of `partial_dir` before this function returns.
    for p in partials_written:
        try:
            p.unlink(missing_ok=True)
        except Exception:
            pass
    return merged


class _ClassScopedArgs:
    """Wraps the CLI args namespace to inject this class's prompt into
    the agent. ``run_findings_pass`` reads attributes off args via
    getattr; we forward everything except ``question`` and arrange for
    the class's prompt to be the agent's user prompt."""

    def __init__(self, base: Any, spec: CWEClassSpec):
        self._base = base
        self._spec = spec

    def __getattr__(self, name: str):
        # Looked up only if not found in __dict__; forward to wrapped args.
        return getattr(self._base, name)

    @property
    def cwe_class_prompt(self) -> str:
        return f"[{self._spec.id} -- {self._spec.title}]\n\n{self._spec.prompt}"
