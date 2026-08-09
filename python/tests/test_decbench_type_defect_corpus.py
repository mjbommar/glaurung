"""Contracts for the curated DecBench one-edit type defect corpus."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "decbench_scoreboard" / "type-distance-one-9c25fcb.json"


def test_type_distance_one_corpus_is_complete_and_owner_grouped() -> None:
    """Pin all 29 one-edit failures and their semantic ownership."""
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    defects = payload["defects"]

    assert payload["schema_version"] == 1
    assert payload["glaurung_revision"] == "9c25fcb860fb433b59bb24b3f880e8ae3a38a972"
    assert payload["source_type_overlay_sha256"] == (
        "4cbb9613344bf365df9cc6c8e72993a62eb1d14a360576daa89736d991cf596c"
    )
    assert len(defects) == 29
    assert len({defect["key"] for defect in defects}) == 29
    assert all(defect["distance"] == 1 for defect in defects)
    assert all(defect["evidence_owner"] for defect in defects)
    assert all(defect["mismatch"] for defect in defects)
    assert Counter(defect["failure_cluster"] for defect in defects) == {
        "pointer_category": 20,
        "missing_local_identity": 6,
        "integer_width": 2,
        "missing_parameter": 1,
    }
    assert payload["fresh_validation"] == {
        "metric": "official TypeMatchMetric cache_version 4 with caching disabled",
        "scope": "all 29 functions, address-scoped from their real official binaries",
        "parent_revision": "acc3e241cf1314312b18acd165d766bd8ab6ed34",
        "parent_perfect": 13,
        "current_perfect": 20,
        "current_open": 9,
    }
    assert [
        defect["key"] for defect in defects if defect["status"] == "verified_fixed"
    ] == [
        "bash::O0::mksyntax::wcomment",
        "bash::O2-noinline::bash::allocerr",
        "chibios::O2-noinline::ch::nvicEnableVector",
        "cleanflight::O0::cleanflight_DALRCF405::icm20689SpiAccDetect",
        "cleanflight::O2-noinline::cleanflight_DALRCF405::m25p16_enable",
        "crazyflie::O2-noinline::firmware::ld_word",
        "cronie::O2::crontab::strcmp_until",
        "diffutils::O0::diff3::try_help",
        "diffutils::O2-noinline::diff::stophandler",
        "diffutils::O2-noinline::sdiff::lf_skip",
        "diffutils::O2::diff3::try_help",
        "findutils::O0::find::prec_name",
        "freertos::O0::RTOSDemo::vListInitialise",
        "freertos::O2::RTOSDemo::vListInitialiseItem",
        "kmod::O2::kmod::mod_free",
        "libexpat::O0::xmlwf::codepageConvert",
        "libopencm3::O0::usbmidi::usbd_ep_nak_set",
        "libopencm3::O2-noinline::timer::timer_disable_preload",
        "libopencm3::O2::cryptobasic::usart_set_databits",
        "rsyslog::O2::rsyslogd::beginTransaction",
    ]
    assert Counter(defect["status"] for defect in defects) == {
        "verified_fixed": 20,
        "open": 9,
    }
