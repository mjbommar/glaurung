"""`glaurung sigs list|fetch|verify|status|path`.

Run in-process through `glaurung.cli.main.main`, with `GLAURUNG_SIG_DIR`
pointed at a temporary cache, so nothing here touches the user's real one. The
network is never reached: every verb but `fetch` is offline by construction,
and `fetch` is exercised through `--offline` and through a `file://` URL over
a release the test publishes itself.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from glaurung.cli.main import main
from glaurung.sigs import paths

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / "tools" / "publish_signature_set.py"


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Never let a test write to the developer's real signature cache."""
    monkeypatch.setenv(paths.ENV_CACHE_DIR, str(tmp_path / "cache"))
    monkeypatch.delenv(paths.ENV_OFFLINE, raising=False)
    monkeypatch.delenv(paths.ENV_MANIFEST_URL, raising=False)
    return tmp_path / "cache"


def _json(capsys, argv: list[str]) -> tuple[int, object]:
    code = main([*argv, "--json"])
    out = capsys.readouterr().out
    return code, json.loads(out)


# --- the command is registered ------------------------------------------------


def test_sigs_is_in_the_command_registry():
    from glaurung.cli.main import _REGISTRY

    assert "sigs" in _REGISTRY


def test_help_lists_every_verb(capsys):
    with pytest.raises(SystemExit):
        main(["sigs", "--help"])
    out = capsys.readouterr().out
    for verb in ("list", "fetch", "verify", "status", "path"):
        assert verb in out


def test_a_missing_verb_is_an_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["sigs"])
    assert excinfo.value.code != 0


# --- path ---------------------------------------------------------------------


def test_path_prints_every_root(capsys, isolated_cache):
    code, payload = _json(capsys, ["sigs", "path"])
    assert code == 0
    assert payload["cache_root"] == str(isolated_cache)
    assert payload["catalog"].endswith("catalog.json")
    assert Path(payload["schema"]).is_file()
    assert Path(payload["bundled_manifest"]).is_file()
    assert Path(payload["trusted_keys_dir"]).is_dir()


def test_path_for_an_unknown_key_fails(capsys):
    code, payload = _json(capsys, ["sigs", "path", "nosuch/1/v/x86_64"])
    assert code == 1
    assert payload["path"] is None


def test_path_for_a_bundled_key_resolves_before_any_fetch(capsys):
    """A fresh install can locate its bundled blobs with an empty cache."""
    from glaurung.sigs.manifest import Manifest

    key = Manifest.read(paths.bundled_manifest_path()).blobs[0].key
    code, payload = _json(capsys, ["sigs", "path", key])
    assert code == 0
    assert Path(payload["path"]).is_file()


# --- status and list ----------------------------------------------------------


def test_status_on_a_fresh_install(capsys, isolated_cache):
    code, payload = _json(capsys, ["sigs", "status"])
    assert code == 0
    assert payload["cache_exists"] is False
    assert payload["offline"] is False
    assert payload["set"] == "base"
    assert payload["blobs_present"] == 0
    assert payload["trusted_keys"], "no trusted key ships"
    assert payload["verified_utc"] == ""


def test_status_reports_the_offline_flag(capsys, monkeypatch):
    monkeypatch.setenv(paths.ENV_OFFLINE, "1")
    code, payload = _json(capsys, ["sigs", "status"])
    assert code == 0
    assert payload["offline"] is True


def test_list_shows_the_bundled_set(capsys):
    code, payload = _json(capsys, ["sigs", "list"])
    assert code == 0
    assert payload["set"] == "base"
    assert payload["blobs"]
    for row in payload["blobs"]:
        assert len(row["sha256"]) == 64
        assert row["cached"] is True, "bundled blobs are present by definition"


def test_list_filters_by_arch(capsys):
    code, payload = _json(capsys, ["sigs", "list", "--arch", "nonesuch"])
    assert code == 0
    assert payload["blobs"] == []


def test_list_plain_output_is_readable(capsys):
    assert main(["sigs", "list"]) == 0
    out = capsys.readouterr().out
    assert "KEY" in out and "SIGS" in out
    assert "blob(s)" in out
    assert "Cache root:" in out


# --- fetch and verify ---------------------------------------------------------


def test_offline_fetch_installs_the_bundled_set(capsys, isolated_cache):
    code, payload = _json(capsys, ["sigs", "fetch", "--offline"])
    assert code == 0
    assert payload["source"].startswith("bundled:")
    assert payload["downloaded"]
    assert payload["verified_by_key_id"]
    assert (isolated_cache / "catalog.json").is_file()
    assert (isolated_cache / "manifest.json").is_file()


def test_verify_is_clean_after_an_offline_fetch(capsys):
    assert main(["sigs", "fetch", "--offline"]) == 0
    capsys.readouterr()
    code, payload = _json(capsys, ["sigs", "verify"])
    assert code == 0
    assert payload["ok"] is True
    assert payload["problems"] == []
    assert payload["deep"] is True


def test_verify_reports_a_corrupted_cache(capsys, isolated_cache):
    assert main(["sigs", "fetch", "--offline"]) == 0
    capsys.readouterr()
    blobs = [p for p in isolated_cache.iterdir() if len(p.name) == 64]
    assert blobs
    data = bytearray(blobs[0].read_bytes())
    data[5] ^= 0xFF
    blobs[0].write_bytes(bytes(data))

    code, payload = _json(capsys, ["sigs", "verify"])
    assert code == 1
    assert payload["ok"] is False
    assert any("sha256" in problem for problem in payload["problems"])


def test_shallow_verify_does_not_hash(capsys, isolated_cache):
    assert main(["sigs", "fetch", "--offline"]) == 0
    capsys.readouterr()
    blobs = [p for p in isolated_cache.iterdir() if len(p.name) == 64]
    data = bytearray(blobs[0].read_bytes())
    data[5] ^= 0xFF  # same length
    blobs[0].write_bytes(bytes(data))

    code, payload = _json(capsys, ["sigs", "verify", "--shallow"])
    assert code == 0, "a size-only check cannot see an in-place edit, by design"
    assert payload["deep"] is False


def test_fetch_over_a_file_url(capsys, tmp_path, isolated_cache, monkeypatch):
    """A real published release, served from disk, through the real code path."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "libx.flirt.json").write_text(json.dumps({"entries": ["x"] * 30}))
    (corpus / "index.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "libraries": [
                    {
                        "key": "test.x86_64-linux-gnu.libx",
                        "output": "libx.flirt.json",
                        "library_name": "libx-dev",
                        "library_version": "9.9",
                        "variant": "gcc-11-O2",
                        "arch": "x86_64",
                        "image": "test",
                        "unique_signatures": 30,
                    }
                ],
            }
        )
    )
    out = tmp_path / "release"
    key = tmp_path / "k.key"
    published = subprocess.run(
        [
            sys.executable,
            str(PUBLISH),
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            "2026.09.9",
            "--serial",
            "9",
            "--out",
            str(out),
            "--secret-key",
            str(key),
            "--generate-key",
            "--quiet",
            # Serve the blobs from disk and claim no other mirror: a URL that
            # cannot answer would cost a real network attempt in a test.
            "--repo",
            "",
            "--hf-repo",
            "",
            "--r2-base",
            (out / "blobs").as_uri(),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert published.returncode == 0, published.stderr[-2000:]

    # Trust the key that signed it, and point the client at the local copy.
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    (keys_dir / "test.pub").write_text(key.with_suffix(".pub").read_text())
    monkeypatch.setenv(paths.ENV_KEYS_DIR, str(keys_dir))

    url = (out / "manifest.json").as_uri()
    code, payload = _json(capsys, ["sigs", "fetch", "--manifest-url", url])
    assert code == 0
    assert payload["serial"] == 9
    assert payload["downloaded"] == ["libx/9.9/gcc-11-O2/x86_64"]

    capsys.readouterr()
    code, listing = _json(capsys, ["sigs", "list", "--cached-only"])
    assert code == 0
    assert [row["key"] for row in listing["blobs"]] == ["libx/9.9/gcc-11-O2/x86_64"]


def test_fetch_of_an_uncached_set_offline_reports_an_error(capsys, monkeypatch):
    code = main(["sigs", "fetch", "--offline", "--set", "windows"])
    assert code == 2
    assert "Error:" in capsys.readouterr().out


# --- laziness -----------------------------------------------------------------


def test_sigs_does_not_import_the_llm_stack():
    """`glaurung sigs` is an offline cache command; it must stay cheap."""
    probe = (
        "import sys, json, io, contextlib\n"
        "from glaurung.cli.main import main\n"
        "try:\n"
        "    with contextlib.redirect_stdout(io.StringIO()):\n"
        "        main(['sigs', 'status'])\n"
        "except SystemExit:\n    pass\n"
        "print(json.dumps(sorted({m.split('.')[0] for m in sys.modules})))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, cwd=ROOT
    )
    assert result.returncode == 0, result.stderr[-2000:]
    loaded = set(json.loads(result.stdout.strip().splitlines()[-1]))
    for heavy in ("pydantic_ai", "pydantic_graph"):
        assert heavy not in loaded, f"`glaurung sigs status` imported {heavy}"
