import pytest
import glaurung


def test_sum_as_string():
    assert glaurung.sum_as_string(1, 1) == "2"
