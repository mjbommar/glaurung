from __future__ import annotations
from typing import List, Optional

class SearchMatch:
    kind: str
    text: str
    start: int
    end: int
    offset: Optional[int]

def defang(text: str, max_len: int = 4096) -> str: ...
def search_text(
    text: str,
    defang_normalize: bool = True,
    max_matches_total: int = 10_000,
    max_matches_per_kind: int = 1_000,
    time_guard_ms: int = 25,
) -> List[SearchMatch]: ...
def search_bytes(
    data: bytes,
    min_length: int = 4,
    max_samples: int = 40,
    max_scan_bytes: int = 1_048_576,
    time_guard_ms: int = 10,
    defang_normalize: bool = True,
    max_matches_total: int = 10_000,
    max_matches_per_kind: int = 1_000,
) -> List[SearchMatch]: ...
def similarity_score(a: str, b: str, algo: str = "jaro_winkler") -> float: ...
def similarity_best_match(
    query: str,
    candidates: list[str],
    algo: str = "jaro_winkler",
    min_score: float = 0.85,
    max_candidates: int = 10000,
    max_len: int = 128,
) -> Optional[tuple[str, float]]: ...
def similarity_top_k(
    query: str,
    candidates: list[str],
    k: int = 5,
    algo: str = "jaro_winkler",
    min_score: float = 0.6,
    max_candidates: int = 10000,
    max_len: int = 128,
) -> list[tuple[str, float]]: ...
def demangle_text(text: str) -> Optional[tuple[str, str]]: ...
def demangle_list(names: list[str], max: int = 10000) -> list[tuple[str, str, str]]: ...
