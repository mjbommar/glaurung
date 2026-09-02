"""Every documentation path this repository names actually exists.

Two directions, because documentation rots from both ends:

1. **Links inside documents.** A relative markdown link that no longer
   resolves is the ordinary casualty of moving a file, and it is invisible
   until a reader clicks it.
2. **Paths inside code.** Source comments, tests, tools, workflows, and the
   three top-level files cite documents by path, and those citations do not
   move when the file does.
   The rewrite plan lists roughly forty such sites across `src/`,
   `python/glaurung/`, `tools/`, `scripts/`, and `.github/`.

Both halves ignore code: a fenced block or an inline span may contain
regex character classes, register names, and dispatch expressions that look
exactly like markdown links, and none of them are.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

#: Top-level files that carry documentation links of their own.
TOP_LEVEL = ("README.md", "CLAUDE.md", "AGENTS.md")

#: Trees whose text cites documents by path.
CODE_ROOTS = (
    "src",
    "python/glaurung",
    "python/tests",
    "tools",
    "scripts",
    ".github",
)
CODE_SUFFIXES = frozenset(
    {".rs", ".py", ".yml", ".yaml", ".sh", ".toml", ".ini", ".json", ".md"}
)
EXTRA_CODE_FILES = ("pytest.ini", *TOP_LEVEL)

#: Paths that do not resolve today, with the reason each is tolerated. Phase 2
#: of the documentation rewrite clears this list; an entry that stops matching
#: anything is simply unused, so a fix never has to touch this file.
KNOWN_BROKEN: dict[str, str] = {}

MARKDOWN_LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`\n]*`")

#: A `docs/...` string counts as a path claim when it is shaped like one: it
#: names a directory (trailing slash) or a file (an extension on the last
#: segment). A word boundary that is not a `/` or `.` keeps URLs such as
#: `source.android.com/docs/core/...` out of the match.
DOCS_PATH = re.compile(r"(?<![A-Za-z0-9_./-])docs/[A-Za-z0-9_./-]+")
TRAILING_PUNCTUATION = ".,;:!?)]}\"'`*>"


def strip_code(text: str) -> str:
    """Blank out fenced blocks and inline spans, keeping line structure."""
    lines = text.splitlines()
    out: list[str] = []
    fenced = False
    for line in lines:
        if FENCE.match(line):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else INLINE_CODE.sub("``", line))
    return "\n".join(out)


def markdown_files() -> list[Path]:
    files = sorted(DOCS.rglob("*.md")) if DOCS.is_dir() else []
    files += [ROOT / name for name in TOP_LEVEL]
    return [path for path in files if path.is_file()]


def code_files() -> list[Path]:
    files: list[Path] = []
    for root in CODE_ROOTS:
        base = ROOT / root
        if not base.is_dir():
            continue
        files += [
            path
            for path in base.rglob("*")
            if path.is_file() and path.suffix in CODE_SUFFIXES
        ]
    files += [ROOT / name for name in EXTRA_CODE_FILES]
    return sorted({path for path in files if path.is_file()})


def link_targets(path: Path) -> list[str]:
    """Relative link targets in one markdown file, code excluded."""
    targets = []
    for match in MARKDOWN_LINK.finditer(strip_code(path.read_text(errors="ignore"))):
        target = match.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#", "<", "tel:")):
            continue
        target = target.split("#", 1)[0].strip()
        if not target:
            continue
        targets.append(target)
    return targets


def docs_path_claims(path: Path) -> list[str]:
    """`docs/...` strings in one file that are shaped like a path."""
    claims = []
    for match in DOCS_PATH.finditer(path.read_text(errors="ignore")):
        claim = match.group(0).rstrip(TRAILING_PUNCTUATION)
        last = claim.rsplit("/", 1)[-1]
        if claim.endswith("/") or "." in last:
            claims.append(claim)
    return claims


def _relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def test_every_relative_documentation_link_resolves() -> None:
    """A link that 404s is worse than no link: it claims the page exists."""
    broken = []
    for path in markdown_files():
        for target in link_targets(path):
            if target in KNOWN_BROKEN:
                continue
            resolved = (
                (ROOT / target.lstrip("/"))
                if target.startswith("/")
                else (path.parent / target)
            )
            if not resolved.exists():
                broken.append(f"{_relative(path)} -> {target}")

    assert not broken, "unresolvable relative links:\n  " + "\n  ".join(broken)


def test_every_documentation_path_named_in_code_resolves() -> None:
    """Source comments, tools, and workflows cite documents that must exist."""
    broken: dict[str, list[str]] = {}
    for path in code_files():
        for claim in docs_path_claims(path):
            if claim in KNOWN_BROKEN or (ROOT / claim).exists():
                continue
            broken.setdefault(claim, []).append(_relative(path))

    report = "\n  ".join(
        f"{claim} <- {', '.join(sorted(set(sources)))}"
        for claim, sources in sorted(broken.items())
    )
    assert not broken, (
        "documentation paths named in code that do not exist "
        "(re-point the citation, or add it to KNOWN_BROKEN with a reason):"
        f"\n  {report}"
    )


def test_the_known_broken_allowlist_carries_a_reason() -> None:
    """An allowlist without reasons becomes permanent by default."""
    for claim, reason in KNOWN_BROKEN.items():
        assert reason.strip(), claim
        assert not (ROOT / claim.lstrip("/")).exists(), (
            f"{claim} resolves now -- delete its KNOWN_BROKEN entry"
        )


def test_the_checkers_see_something_to_check() -> None:
    """A regex that silently matches nothing would make both tests vacuous."""
    assert len(markdown_files()) > 100
    assert sum(len(link_targets(path)) for path in markdown_files()) > 100
    assert sum(len(docs_path_claims(path)) for path in code_files()) > 10
