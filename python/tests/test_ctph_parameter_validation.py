"""CTPH parameters that used to panic the interpreter now raise ValueError.

`ctph_hash_bytes` and `ctph_hash_path` passed `window_size` and `digest_size`
straight into the hasher. `window_size = 0` reached `pop_front().unwrap()` on
an empty deque; `digest_size` is used as `% (digest_size as u8)`, so both `0`
and `256` (which truncates to `0u8`) were a division by zero. All three raised
`PanicException` from Python -- a caller who passed a number got a poisoned
Rust thread rather than an error about their argument.

`crate::triage::api` already guarded the same two fields on its own path, so
the hazard was known on one route and unguarded on the other. Found by reading
the bindings while building the similarity corpus, not by any existing test.
"""

from __future__ import annotations

import pytest

import glaurung


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"window_size": 0}, "window_size"),
        ({"digest_size": 0}, "digest_size"),
        # 256 truncates to 0u8, which is the same division by zero by a
        # different route -- the one a bounds check on "> 0" alone would miss.
        ({"digest_size": 256}, "digest_size"),
    ],
)
def test_degenerate_parameters_raise_rather_than_panic(kwargs, expected):
    with pytest.raises(ValueError, match=expected):
        glaurung.similarity.ctph_hash_bytes(b"A" * 64, **kwargs)


def test_the_boundary_values_themselves_are_accepted():
    """1 and 255 are legal; the rejection must not be off by one."""
    assert glaurung.similarity.ctph_hash_bytes(b"A" * 64, window_size=1)
    assert glaurung.similarity.ctph_hash_bytes(b"A" * 64, digest_size=1)
    assert glaurung.similarity.ctph_hash_bytes(b"A" * 64, digest_size=255)


def test_defaults_still_work():
    """A vacuity guard: the tests above would pass if the function always raised."""
    assert glaurung.similarity.ctph_hash_bytes(b"A" * 64)
