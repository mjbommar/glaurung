"""The guard that stops `defuse_baseline.json` from ratcheting the wrong way.

WHY THIS EXISTS
---------------
`python/tests/test_decompiler_defuse_census.py` is a two-sided ratchet:
``test_no_lane_emits_more_undefined_reads_than_recorded`` fails when a lane's
totals RISE, and ``test_improvements_require_a_baseline_refresh`` fails when
they FALL — and the second failure's message instructs you to run
``tools/gen_defuse_baseline.py``. That writer had no guard at all: it rewrote
the file from whatever the current measurement was. So the documented,
frequently-required workflow (also required whenever a fixture is added, because
new fixtures add new cells) silently reset the ceiling *upward*.

It already happened, unnoticed. Between ``9dfd8457`` and ``fd0b6455`` — one
commit — ``rustc:O0`` went 7525 -> 7535 undefined reads and ``rustc:O2`` went
4451 -> 4457, and a per-cell diff of every tracked ``required`` cell across
those two commits shows 0 added, 0 removed, 0 changed. All sixteen regressions
were in functions the manifest makes no per-function claim about, so no per-cell
assertion could see them; only the aggregate integer moved, and regenerating
overwrote it. This is the same shape as the fitness ratchet's drift, fixed in
``be307496``.

WHAT IT DOES
------------
A regeneration may LOWER any ceiling and may ADD cells for free. Only an upward
move needs an argument:

    tools/gen_defuse_baseline.py \\
        --accept-regression 'rustc:O0=+10: aggregate-return work, see fd0b6455'

The accepted movement is then written INTO the baseline under
``accepted_regressions``, so the next person to regenerate inherits the list and
has to look at it, exactly as ``tools/fitness_report.py`` does. Unlike that one,
this guard also REFUSES the write, because the census ceiling is a correctness
measure rather than a code-shape measure: an undefined read in emitted C is a
wrong-code bug, and there is no volume of routine refactoring that legitimately
moves it.

NEW FIXTURES MUST STAY FRICTIONLESS
-----------------------------------
Adding a fixture adds emitted functions, and those functions can carry
violations, so a new fixture can legitimately raise a lane total without
anything having got worse. The line drawn here is at FIXTURE granularity:
``fixture_lane_totals`` records each ``fixture:cc:opt`` lane's own counts, so a
rise is split into the part contributed by fixture-lanes the baseline already
knew about (``attributable``) and the part contributed by fixture-lanes that are
new (free). Only the attributable part needs a reason.

That line is exact for "did a fixture I already tracked get worse", and it is
deliberately NOT finer: a rise inside an existing fixture is charged to the
regeneration even when the cause is a newly emitted function in that fixture.
Both of those are decompiler behaviour changes on unchanged input, so both
should have to say why.

When the baseline predates this schema (no ``fixture_lane_totals``), nothing can
be attributed and the FULL rise needs a reason. That is the conservative
direction, and the reason is free text — "new fixture 197 adds 12 functions" is
a perfectly good one.
"""

from __future__ import annotations

import re
from typing import Any

#: The two per-lane ceilings the census gate enforces.
LANE_MEASURES = ("violations", "functions_with_violations")

#: Default measure when `--accept-regression` names a lane without one.
DEFAULT_MEASURE = "violations"

SUMMARY_MEASURES = (
    "functions_emitted",
    "functions_with_violations",
    "violations",
)

#: `LANE[/MEASURE]=+DELTA: REASON`. The lane name itself contains a colon
#: (`rustc:O0`) and a required-function key contains three
#: (`195_x:gcc:O0:make_quad`), which is why the measure is `/`-separated and the
#: reason is split on the FIRST colon after the delta.
_ACCEPT = re.compile(r"^\s*(?P<key>[^=]+?)\s*=\s*\+(?P<delta>\d+)\s*:\s*(?P<why>.+)$")


class AcceptSyntaxError(ValueError):
    """A `--accept-regression` argument that could not be parsed."""


def language_totals(lane_totals: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """Roll compiler lanes into explicit C and Rust reporting totals."""
    totals = {
        language: {measure: 0 for measure in SUMMARY_MEASURES}
        for language in ("c", "rust")
    }
    for lane, measurements in lane_totals.items():
        language = "rust" if lane.startswith("rustc:") else "c"
        for measure in SUMMARY_MEASURES:
            totals[language][measure] += int(measurements.get(measure, 0))
    return totals


class Regression:
    """One upward movement the regeneration would record.

    Attributes:
        kind: ``lane_total`` or ``required_function``.
        key: The lane (``rustc:O0``) or required cell
            (``195_x:gcc:O0:make_quad``) that moved.
        measure: Which count moved; see `LANE_MEASURES`.
        before: The value the committed baseline records.
        after: The value this census measured.
        attributable: How much of ``after - before`` is charged to input the
            baseline already covered. Equal to the full delta unless
            ``fixture_lane_totals`` let some of it be credited to a new fixture.
        detail: Human-readable note about the attribution, or ``""``.
    """

    def __init__(
        self,
        kind: str,
        key: str,
        measure: str,
        before: int,
        after: int,
        attributable: int,
        detail: str = "",
    ) -> None:
        self.kind = kind
        self.key = key
        self.measure = measure
        self.before = before
        self.after = after
        self.attributable = attributable
        self.detail = detail

    @property
    def token(self) -> str:
        """The `--accept-regression` argument that would accept this movement."""
        suffix = "" if self.measure == DEFAULT_MEASURE else f"/{self.measure}"
        return f"{self.key}{suffix}=+{self.attributable}"

    def describe(self) -> str:
        """One line naming the movement and the flag that would accept it."""
        line = (
            f"{self.key}/{self.measure}: {self.before} -> {self.after} "
            f"(+{self.after - self.before})"
        )
        if self.detail:
            line += f" [{self.detail}]"
        return f"{line}\n      accept with:  --accept-regression '{self.token}: <why>'"

    def record(self, reason: str) -> dict[str, Any]:
        """The entry written into the baseline's ``accepted_regressions``."""
        return {
            "attributable_delta": self.attributable,
            "delta": self.after - self.before,
            "from": self.before,
            "key": self.key,
            "kind": self.kind,
            "measure": self.measure,
            "reason": reason,
            "to": self.after,
        }


def parse_acceptances(args: list[str]) -> dict[tuple[str, str], tuple[int, str]]:
    """Parse `--accept-regression` arguments into {(key, measure): (delta, why)}.

    Args:
        args: Raw ``LANE[/MEASURE]=+DELTA: REASON`` strings.

    Returns:
        A mapping from the movement's identity to its accepted delta and reason.

    Raises:
        AcceptSyntaxError: On an unparseable argument, an unknown measure, a
            duplicate key, or an empty reason.
    """
    out: dict[tuple[str, str], tuple[int, str]] = {}
    for arg in args:
        match = _ACCEPT.match(arg)
        if not match:
            raise AcceptSyntaxError(
                f"cannot parse --accept-regression {arg!r}; expected "
                "'LANE[/MEASURE]=+DELTA: reason', e.g. "
                "'rustc:O0=+10: aggregate-return work, see fd0b6455'"
            )
        key, _, measure = match.group("key").partition("/")
        measure = measure or DEFAULT_MEASURE
        if measure not in LANE_MEASURES and measure != "undefined_reads":
            raise AcceptSyntaxError(
                f"unknown measure {measure!r} in {arg!r}; expected one of "
                f"{', '.join((*LANE_MEASURES, 'undefined_reads'))}"
            )
        why = match.group("why").strip()
        if not why:
            raise AcceptSyntaxError(f"empty reason in {arg!r}")
        identity = (key.strip(), measure)
        if identity in out:
            raise AcceptSyntaxError(f"duplicate --accept-regression for {key!r}")
        out[identity] = (int(match.group("delta")), why)
    return out


def _fixture_lane_credit(
    lane: str, measure: str, current: dict[str, Any], baseline: dict[str, Any]
) -> tuple[int | None, str]:
    """How much of a lane's rise is charged to fixtures the baseline knew about.

    Returns:
        ``(attributable, detail)``, or ``(None, why-not)`` when neither side
        carries the per-fixture breakdown and nothing can be attributed.
    """
    now = current.get("fixture_lane_totals")
    was = baseline.get("fixture_lane_totals")
    if not isinstance(now, dict) or not isinstance(was, dict):
        return None, "no per-fixture breakdown in the baseline"
    attributable = 0
    fresh: list[str] = []
    for cell, totals in now.items():
        # `fixture:cc:opt` -> the `cc:opt` lane it rolls up into.
        if cell.split(":", 1)[1] != lane:
            continue
        before = was.get(cell)
        if before is None:
            if totals.get(measure, 0):
                fresh.append(cell)
            continue
        attributable += totals.get(measure, 0) - before.get(measure, 0)
    attributable = max(0, attributable)
    if fresh:
        detail = (
            f"{len(fresh)} new fixture-lane(s) not charged, e.g. {sorted(fresh)[0]}"
        )
    else:
        detail = "all fixture-lanes were already tracked"
    return attributable, detail


def find_regressions(
    current: dict[str, Any], baseline: dict[str, Any]
) -> list[Regression]:
    """Every upward movement this census makes against the committed baseline.

    Improvements and unchanged values are never reported, and cells absent from
    the baseline are never reported: adding a fixture must stay frictionless.

    Args:
        current: A freshly measured ``defuse.defuse_report()``.
        baseline: The committed ``defuse_baseline.json`` contents.

    Returns:
        The movements, lane totals first, each needing an explicit acceptance.
    """
    found: list[Regression] = []
    recorded_lanes = baseline.get("lane_totals") or {}
    for lane, before in sorted(recorded_lanes.items()):
        after = (current.get("lane_totals") or {}).get(lane)
        if after is None:
            continue
        for measure in LANE_MEASURES:
            rise = after.get(measure, 0) - before.get(measure, 0)
            if rise <= 0:
                continue
            credited, detail = _fixture_lane_credit(lane, measure, current, baseline)
            attributable = rise if credited is None else min(rise, credited)
            if attributable <= 0:
                continue
            found.append(
                Regression(
                    "lane_total",
                    lane,
                    measure,
                    before.get(measure, 0),
                    after.get(measure, 0),
                    attributable,
                    detail,
                )
            )
    recorded_required = baseline.get("required") or {}
    for cell, before_list in sorted(recorded_required.items()):
        after_list = (current.get("required") or {}).get(cell)
        if after_list is None:
            continue
        new = sorted(_normalised(after_list) - _normalised(before_list))
        if not new:
            continue
        # Report the RAW message, not the normalised one: the normalisation is
        # for deciding whether something moved, and a reader chasing it wants
        # the actual variable name.
        new = [
            m for m in sorted(set(after_list)) if _normalise_violation(m) in set(new)
        ] or new
        found.append(
            Regression(
                "required_function",
                cell,
                "undefined_reads",
                len(before_list),
                len(after_list),
                len(new),
                f"new: {new[0]}" if len(new) == 1 else f"{len(new)} new, e.g. {new[0]}",
            )
        )
    return found


#: Temporary and slot names carry a serial number that renumbers whenever a
#: function emits one more or one fewer temporary. Comparing the raw strings
#: makes that renumbering look like one violation resolved and one appearing.
_SERIAL = re.compile(r"\b(var|local_|stack_|t)[0-9a-f]+\b")


def _normalise_violation(message: str) -> str:
    """`message` with generated serial numbers replaced by a placeholder.

    A violation is identified by WHAT is undefined and WHERE, not by the number
    the renderer happened to assign. `var79 is read but never defined` and
    `var81 is read but never defined` are the same violation at the same
    position when the only thing between them is a lifter change that emitted
    one more temporary earlier in the function -- which is exactly what happened
    to `165_bitstream_reader:clang:O2:bit165_cross_check` when the byte-view
    `not` fix landed. The ratchet reported `1 -> 1 (+0)` and still demanded a
    justification, because set-difference on the raw strings yielded one
    resolved and one new.

    That false positive is not rare: any lifter change that alters how many
    temporaries a function emits renumbers everything after it. Left uncorrected
    it trains the reader to accept without looking, which is precisely what the
    acceptance flag exists to prevent.
    """
    return _SERIAL.sub(r"\1#", message)


def _normalised(messages: list[str]) -> set[str]:
    return {_normalise_violation(m) for m in messages}


def apply_acceptances(
    regressions: list[Regression], accepted: dict[tuple[str, str], tuple[int, str]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Match measured movements against the acceptances the caller passed.

    The delta must match EXACTLY. An acceptance that names a smaller number than
    the movement would let the rest through unseen, and one that names a larger
    number would pre-authorise drift that has not happened yet — which is the
    failure this whole module exists to stop.

    Args:
        regressions: What `find_regressions` measured.
        accepted: What `parse_acceptances` parsed.

    Returns:
        ``(records, problems)``. ``records`` are baseline entries for the
        movements that were accepted; ``problems`` describe every movement that
        was not, plus every acceptance that matched nothing.
    """
    records: list[dict[str, Any]] = []
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    for regression in regressions:
        identity = (regression.key, regression.measure)
        claim = accepted.get(identity)
        if claim is None:
            problems.append(f"UNACCEPTED  {regression.describe()}")
            continue
        seen.add(identity)
        delta, why = claim
        if delta != regression.attributable:
            problems.append(
                f"WRONG DELTA {regression.key}/{regression.measure}: you accepted "
                f"+{delta}, the census measured +{regression.attributable}\n"
                f"      accept with:  --accept-regression '{regression.token}: {why}'"
            )
            continue
        records.append(regression.record(why))
    for identity in sorted(set(accepted) - seen):
        problems.append(
            f"STALE       --accept-regression for {identity[0]}/{identity[1]} "
            "matched no measured regression; remove it"
        )
    return records, problems


def carry_forward(
    previous: dict[str, Any] | None, records: list[dict[str, Any]], keep: int = 50
) -> list[dict[str, Any]]:
    """The ``accepted_regressions`` list to write into the new baseline.

    The history is carried INSIDE the baseline for the reason `be307496` gives:
    a ratchet regenerated by the change that would have failed it is a logbook,
    and the drift is only visible if the evidence of the previous step survives
    the next one.
    """
    history = list((previous or {}).get("accepted_regressions") or [])
    return (history + records)[-keep:]


def drift_lines(history: list[dict[str, Any]]) -> list[str]:
    """Say out loud how far each ceiling has been walked up, and how often."""
    if not history:
        return []
    first: dict[tuple[str, str], int] = {}
    last: dict[tuple[str, str], int] = {}
    for entry in history:
        identity = (entry.get("key", "?"), entry.get("measure", "?"))
        first.setdefault(identity, entry.get("from", 0))
        last[identity] = entry.get("to", 0)
    lines = [f"accepted regressions recorded: {len(history)}"]
    for identity in sorted(first):
        was, is_now = first[identity], last[identity]
        if was != is_now:
            lines.append(
                f"  drift since first recorded: {identity[0]}/{identity[1]}: "
                f"{was} -> {is_now} (+{is_now - was})"
            )
    return lines
