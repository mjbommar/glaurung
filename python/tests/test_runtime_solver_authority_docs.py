import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HYBRID_DOCS = (
    ROOT / "docs" / "architecture" / "runtime-instruction-trace.md",
    ROOT / "docs" / "development" / "roadmap" / "runtime-analysis.md",
    ROOT / "docs" / "design" / "hybrid-analysis-data-model" / "README.md",
    ROOT
    / "docs"
    / "design"
    / "hybrid-analysis-data-model"
    / "objective-ladder.md",
)


def test_runtime_counterfactual_docs_name_axeyum_as_authority() -> None:
    combined = "\n".join(path.read_text() for path in HYBRID_DOCS)

    runtime_trace = HYBRID_DOCS[0].read_text()
    assert re.search(r"\b(?:z3|cvc5|bitwuzla)\b", runtime_trace, re.IGNORECASE) is None
    assert "authoritative native-Axeyum" in combined
