"""`docs/reference/provenance.md` cannot drift from `provenance.py`.

The `set_by` ladder used to appear in five documents and be right in none of
them. The repair was to generate the table from the one place the ranking
exists and keep the essay beside it by hand; this file is what stops the
generated half from going stale again, and what stops a regeneration from
eating the hand-written half.

The comparison ignores the commit line in the header. That line records when
the document was last regenerated, which is not a fact about the ladder --
comparing it would make every commit that did not touch `provenance.py` fail.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools" / "gen_provenance_reference.py"
REFERENCE = ROOT / "docs" / "reference" / "provenance.md"
SOURCE = ROOT / "python" / "glaurung" / "llm" / "kb" / "provenance.py"

#: A `"name": <int>,` entry in the frozen priority table. Deliberately a
#: second, cruder reading of the same file than the generator's `ast` walk:
#: two independent derivations agreeing is what makes the table trustworthy,
#: and a regex that matched nothing would make this file vacuous.
ENTRY = re.compile(r'^\s*"([a-z_]+)":\s*(\w+),', re.MULTILINE)


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_provenance_reference", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_generator_is_present() -> None:
    assert GENERATOR.is_file(), GENERATOR


def test_the_reference_matches_the_source() -> None:
    """The document on disk is what the generator produces today."""
    module = _load()
    generated = module.generate()
    on_disk = REFERENCE.read_text()
    assert module.without_commit(on_disk) == module.without_commit(generated), (
        "docs/reference/provenance.md is stale -- run "
        "`uv run python tools/gen_provenance_reference.py`"
    )


def test_every_set_by_value_in_the_code_appears_in_the_table() -> None:
    """Read the priority table a second way and require the same values."""
    values = {name for name, _ in ENTRY.findall(SOURCE.read_text())}
    assert len(values) >= 10, values

    table = REFERENCE.read_text().split("<!-- prose:start -->", 1)[0]
    missing = sorted(value for value in values if f"`{value}`" not in table)
    assert not missing, f"absent from the generated ladder: {missing}"


def test_the_ranks_are_the_ones_the_code_assigns() -> None:
    """A row's rank column is the number the source gives that value."""
    text = SOURCE.read_text()
    auto_match = re.search(r"AUTO_PRIORITY:\s*Final\[int\]\s*=\s*(\d+)", text)
    assert auto_match is not None, "AUTO_PRIORITY is no longer an int literal"
    auto = int(auto_match.group(1))
    ranks = {
        name: auto if raw == "AUTO_PRIORITY" else int(raw)
        for name, raw in ENTRY.findall(text)
    }
    assert ranks.get("manual") == max(ranks.values()), "manual must outrank everything"

    table = REFERENCE.read_text().split("<!-- prose:start -->", 1)[0]
    rows = {
        int(rank): {cell.strip(" `") for cell in values.split(",")}
        for rank, values in re.findall(
            r"^\|\s*(\d+)\s*\|([^|]+)\|", table, re.MULTILINE
        )
    }
    assert rows, "no ladder rows were parsed out of the reference"

    for name, rank in ranks.items():
        assert name in rows.get(rank, set()), f"{name} should be on the {rank} row"


def test_the_hand_written_prose_survives_a_regeneration() -> None:
    """Regenerating must not eat the essay the markers protect."""
    module = _load()
    prose = module.existing_prose(REFERENCE)
    assert len(prose.splitlines()) > 20, "the prose section looks empty"

    regenerated = module.generate()
    assert prose.strip() in regenerated
    assert regenerated.count(module.PROSE_START) == 1
    assert regenerated.count(module.PROSE_END) == 1


def test_the_document_declares_its_kind_and_status() -> None:
    """`test_docs_manifest.py` enforces this for every doc; a generated file
    has to carry it through the generator rather than by hand."""
    head = "\n".join(REFERENCE.read_text().splitlines()[:5])
    assert "**Kind:** reference" in head
    assert "**Status:** generated" in head
