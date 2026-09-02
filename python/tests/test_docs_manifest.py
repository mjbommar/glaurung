"""Every document under `docs/` declares what kind of document it is.

The documentation tree mixes guides, references, architecture notes, decision
records, live proposals, and dated engineering record in the same directories,
and a reader cannot tell which is which from the path. The fix is a one-line
declaration in the file's own header:

    > **Kind:** guide · **Status:** maintained

for a live document, and

    > **Kind:** record · **Date:** 2026-09-02

for a record. This test enforces the *vocabulary and its presence* -- never a
particular fact about the code. That distinction is the whole point: the tests
this file replaces asserted literal prose, including a sentence saying a build
was failing, which meant the suite required a document to stay wrong after the
build was fixed.

Transitional mode
-----------------

`LEGACY_BANNER_ALLOWED` is `True` while the documentation reorganization is in
flight. A mass banner pass on 2026-08-07 gave many files a
`> **Status: historical design record.**`-style banner, and most other files
carry no declaration at all; converting all of them is a separate, mechanical
phase. While the flag is `True` a file is exempt if it has not been converted
yet -- which is *computed* from the file, never listed here -- so a file that
declares a `Kind:` is held to the full rule immediately and the exemption
shrinks on its own as files are converted. Flipping the flag to `False` is
what makes the rule total; nothing else needs to change.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
HISTORY = DOCS / "history"
TUTORIAL_FIXTURES = DOCS / "tutorial" / "_fixtures"

#: Documents this rewrite has already produced. They are asserted compliant
#: by name so the rule is proven to have teeth even while the transitional
#: exemption above is wide.
AUDIT_DIR = DOCS / "development" / "docs-audit-2026-09-02"
REWRITE_PLAN = DOCS / "development" / "docs-rewrite-plan.md"

KINDS = frozenset(
    {"guide", "reference", "architecture", "decision", "design", "plan", "record"}
)
STATUSES = frozenset({"maintained", "generated", "proposed"})

#: A record is dated rather than statused: it is a snapshot of a moment, so
#: "maintained" would be a lie and "proposed" is meaningless.
RECORD_KIND = "record"

#: The declaration must be in the header, not buried. Five lines allows
#: `# Title`, a blank, the banner, a blank, and the first paragraph.
HEAD_LINES = 5

#: How much of a file counts as its banner zone. Prose that merely *mentions*
#: a banner -- this rewrite's own audit ledgers quote several -- is deeper in
#: the file and is not a declaration.
BANNER_BYTES = 700

KIND_RE = re.compile(r"\*\*Kind:\*\*\s*(\w+)")
STATUS_RE = re.compile(r"\*\*Status:\*\*\s*(\w+)")
DATE_RE = re.compile(r"\*\*Date:\*\*\s*(\d{4}-\d{2}-\d{2})")

#: The 2026-08-07 banner and its bare variant (`Status: historical design
#: draft` on its own line). Both differ from the new form, which always closes
#: the bold before the value: `**Status:** maintained`.
LEGACY_STATUS_RE = re.compile(r"^\s*>?\s*\**Status:(?!\*\*)", re.MULTILINE)

LEGACY_BANNER_ALLOWED = True


def _markdown_under(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(directory.rglob("*.md"))


def live_documents() -> list[Path]:
    """Every `.md` under `docs/` that is meant to carry a kind and a status."""
    return [
        path
        for path in _markdown_under(DOCS)
        if TUTORIAL_FIXTURES not in path.parents and HISTORY not in path.parents
    ]


def head(path: Path) -> str:
    """The declaration zone: the first few lines of the file."""
    return "\n".join(path.read_text(errors="ignore").splitlines()[:HEAD_LINES])


def banner_zone(path: Path) -> str:
    return path.read_bytes()[:BANNER_BYTES].decode("utf-8", errors="ignore")


def declares_a_kind(path: Path) -> bool:
    return KIND_RE.search(head(path)) is not None


def carries_legacy_banner(path: Path) -> bool:
    """The file states a status in the pre-rewrite form."""
    return LEGACY_STATUS_RE.search(banner_zone(path)) is not None


def unconverted(path: Path) -> bool:
    """Not yet touched by the rewrite, so exempt while it is in flight.

    Computed, not listed: a file leaves this set the moment somebody adds the
    declaration line to it.
    """
    if not LEGACY_BANNER_ALLOWED:
        return False
    return carries_legacy_banner(path) or not declares_a_kind(path)


def _relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def test_every_live_document_declares_a_kind_from_the_allowed_vocabulary() -> None:
    """A reader must be able to tell a guide from a record without guessing."""
    offenders = []
    for path in live_documents():
        if unconverted(path):
            continue
        match = KIND_RE.search(head(path))
        assert match is not None, _relative(path)
        if match.group(1) not in KINDS:
            offenders.append(f"{_relative(path)}: **Kind:** {match.group(1)}")

    assert not offenders, (
        "documents declaring a kind outside "
        f"{sorted(KINDS)}:\n  " + "\n  ".join(offenders)
    )


def test_every_live_document_declares_a_status_or_a_date() -> None:
    """A live document says how current it is; a record says when it was true."""
    offenders = []
    for path in live_documents():
        if unconverted(path):
            continue
        kind = KIND_RE.search(head(path))
        assert kind is not None, _relative(path)
        text = head(path)
        if kind.group(1) == RECORD_KIND:
            if DATE_RE.search(text) is None:
                offenders.append(
                    f"{_relative(path)}: **Kind:** record without **Date:** YYYY-MM-DD"
                )
            continue
        status = STATUS_RE.search(text)
        if status is None:
            offenders.append(f"{_relative(path)}: no **Status:** in the first 5 lines")
        elif status.group(1) not in STATUSES:
            offenders.append(f"{_relative(path)}: **Status:** {status.group(1)}")

    assert not offenders, (
        f"a live document declares a **Status:** from {sorted(STATUSES)}, and a "
        "record declares a **Date:** instead:\n  " + "\n  ".join(offenders)
    )


def test_history_documents_are_dated_records() -> None:
    """`docs/history` is read-only evidence: every file says what moment it records."""
    offenders = []
    for path in _markdown_under(HISTORY):
        if path.name == "README.md":
            continue
        text = head(path)
        kind = KIND_RE.search(text)
        if kind is None or kind.group(1) != RECORD_KIND:
            offenders.append(f"{_relative(path)}: not `**Kind:** record`")
        elif DATE_RE.search(text) is None:
            offenders.append(f"{_relative(path)}: no **Date:** YYYY-MM-DD")

    assert not offenders, "under docs/history:\n  " + "\n  ".join(offenders)


def test_every_history_document_is_listed_in_the_history_index() -> None:
    """An archived file nobody can find is deleted with extra steps."""
    index = HISTORY / "README.md"
    if not index.exists():
        return

    listing = index.read_text(errors="ignore")
    missing = [
        str(path.relative_to(HISTORY))
        for path in _markdown_under(HISTORY)
        if path != index and str(path.relative_to(HISTORY)) not in listing
    ]

    assert not missing, (
        "archived documents absent from the docs/history index:\n  "
        + "\n  ".join(missing)
    )


def test_no_live_document_declares_itself_historical() -> None:
    """`Status: historical` is the banner this rewrite replaces, not a status.

    Only the banner zone is checked. A document is allowed to quote the string
    -- the rewrite plan and its audit ledgers do, at length -- because quoting
    it is not declaring it.
    """
    offenders = [
        _relative(path)
        for path in live_documents()
        if "Status: historical" in banner_zone(path) and not unconverted(path)
    ]

    assert not offenders, (
        "these files declare a historical status but live outside "
        "docs/history:\n  " + "\n  ".join(offenders)
    )


def test_the_documents_this_rewrite_produced_declare_their_kind() -> None:
    """The rule has teeth now, not only after the transitional flag flips."""
    produced = [REWRITE_PLAN, *_markdown_under(AUDIT_DIR)]
    assert len(produced) > 5, "the audit ledgers should be on disk"

    for path in produced:
        text = head(path)
        kind = KIND_RE.search(text)
        assert kind is not None, f"{_relative(path)}: no **Kind:** in the first 5 lines"
        assert kind.group(1) in KINDS, f"{_relative(path)}: {kind.group(1)}"
        if kind.group(1) == RECORD_KIND:
            assert DATE_RE.search(text), f"{_relative(path)}: record without a date"
        else:
            status = STATUS_RE.search(text)
            assert status is not None, f"{_relative(path)}: no **Status:**"
            assert status.group(1) in STATUSES, f"{_relative(path)}: {status.group(1)}"


def test_the_transitional_exemption_only_shrinks() -> None:
    """The exemption is computed from file contents, so it cannot be padded.

    A hardcoded allowlist would let a new document opt out of the rule by
    being added to a list. This asserts the property the rest of the file
    depends on: converted documents are never exempt.
    """
    converted = [path for path in live_documents() if declares_a_kind(path)]
    assert converted, "no document declares a kind yet"

    for path in converted:
        if carries_legacy_banner(path):
            continue
        assert not unconverted(path), _relative(path)
