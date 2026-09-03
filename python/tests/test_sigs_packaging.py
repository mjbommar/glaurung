"""The bundled fallback ships in the wheel, and resolves without a cwd.

`src/flirt/mod.rs`'s `default_library_path` resolves `data/sigs/…` relative to
`std::env::current_dir()`. That is the defect this file guards against
repeating: a cwd-relative default means the shipped signature library is found
only when you happen to run from a source checkout, and `pip install glaurung`
ships no signature data at all.

So two layouts have to work, and both are checked from `__file__` alone:

* the **source tree**, where `data/sigs/` is at the repository root, and
* an **installed wheel**, where maturin's `include` preserves the path
  relative to the project root for any file outside `python-source`, so
  `data/sigs/*` lands beside the `glaurung` package in site-packages.

Measured on 2026-09-03 with `uv run maturin build`: the wheel contains
`data/sigs/manifest.schema.json`, `data/sigs/bundled-manifest.json`,
`data/sigs/bundled-manifest.json.minisig`, `data/sigs/NOTICE`,
`data/sigs/base/*` and `data/sigs/trusted-keys/*` at the archive root, which is
the layout the second candidate below resolves.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import tomllib
from pathlib import Path

from glaurung.sigs import manifest as manifest_mod
from glaurung.sigs import paths

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "sigs"

#: The bundled fallback is a convenience, not the corpus. The real set is 171
#: blobs and 125 MB; what ships in the wheel is the demo library plus one
#: small real one (libz, 109 signatures, 68 KiB). Keep it under a quarter of a
#: megabyte or it stops being a fallback and starts being a payload.
BUNDLED_BYTE_CAP = 256 * 1024


def _load_paths_module_from(directory: Path):
    """Import `paths.py` from an arbitrary location, by file.

    `paths.py` deliberately imports nothing from its own package, so it can be
    loaded standalone -- which is what lets this test check the *installed*
    layout without installing anything.
    """
    target = directory / "glaurung" / "sigs" / "paths.py"
    spec = importlib.util.spec_from_file_location("_probe_paths", target)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- packaging ---------------------------------------------------------------


def test_pyproject_ships_the_bundled_data_in_the_wheel():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    include = config["tool"]["maturin"]["include"]
    for pattern in (
        "data/sigs/manifest.schema.json",
        "data/sigs/bundled-manifest.json",
        "data/sigs/bundled-manifest.json.minisig",
        "data/sigs/base/*",
        "data/sigs/trusted-keys/*",
    ):
        assert pattern in include, (
            f"{pattern!r} is not in [tool.maturin].include, so a wheel would "
            "ship without it and a fresh install would have no signatures"
        )


def test_every_included_pattern_matches_something():
    """An include pattern matching nothing is a silently empty wheel entry."""
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    for pattern in config["tool"]["maturin"]["include"]:
        if not pattern.startswith("data/sigs/"):
            continue
        assert list(ROOT.glob(pattern)), f"{pattern!r} matches no file"


def test_the_bundled_set_stays_small():
    total = sum(p.stat().st_size for p in DATA.rglob("*") if p.is_file())
    assert total < BUNDLED_BYTE_CAP, (
        f"data/sigs/ is {total} bytes, over the {BUNDLED_BYTE_CAP}-byte cap. "
        "The bundled set is a fallback; the corpus goes through the release "
        "channel, not the wheel."
    )


# --- path resolution ---------------------------------------------------------


def test_the_source_tree_layout_resolves():
    assert paths.bundled_data_dir() == DATA
    assert paths.schema_path().is_file()
    assert paths.bundled_manifest_path().is_file()
    assert paths.bundled_signature_path().is_file()
    assert list(paths.keys_dir().glob("*.pub"))


def test_resolution_does_not_depend_on_the_cwd(monkeypatch, tmp_path):
    """The whole reason this module exists."""
    monkeypatch.chdir(tmp_path)
    assert paths.bundled_data_dir() == DATA
    assert paths.schema_path().is_file()


def test_the_installed_wheel_layout_resolves(tmp_path, monkeypatch):
    """Reproduce site-packages exactly, and resolve from there.

    `<site-packages>/glaurung/sigs/paths.py` with `<site-packages>/data/sigs/`
    beside the package -- which is where `uv run maturin build` was measured to
    put it.
    """
    site = tmp_path / "site-packages"
    package = site / "glaurung" / "sigs"
    package.mkdir(parents=True)
    (site / "glaurung" / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    shutil.copy(ROOT / "python" / "glaurung" / "sigs" / "paths.py", package)
    shutil.copytree(DATA, site / "data" / "sigs")

    monkeypatch.delenv(paths.ENV_DATA_DIR, raising=False)
    monkeypatch.chdir(tmp_path.parent)
    module = _load_paths_module_from(site)

    assert module.bundled_data_dir() == site / "data" / "sigs"
    assert module.schema_path().is_file()
    assert module.bundled_manifest_path().is_file()
    assert list(module.keys_dir().glob("*.pub"))


def test_a_distribution_missing_the_data_reports_a_missing_file(tmp_path, monkeypatch):
    """Not a missing directory, and not a crash: a nameable missing file."""
    site = tmp_path / "site-packages"
    package = site / "glaurung" / "sigs"
    package.mkdir(parents=True)
    shutil.copy(ROOT / "python" / "glaurung" / "sigs" / "paths.py", package)
    monkeypatch.delenv(paths.ENV_DATA_DIR, raising=False)

    module = _load_paths_module_from(site)
    assert not module.schema_path().is_file()
    assert module.schema_path().name == "manifest.schema.json"


def test_the_env_override_wins(monkeypatch, tmp_path):
    monkeypatch.setenv(paths.ENV_DATA_DIR, str(tmp_path))
    assert paths.bundled_data_dir() == tmp_path


def test_the_cache_root_follows_glaurung_sig_dir(monkeypatch, tmp_path):
    """The same variable the Rust loader consults first."""
    monkeypatch.setenv(paths.ENV_CACHE_DIR, str(tmp_path / "elsewhere"))
    assert paths.cache_root() == tmp_path / "elsewhere"
    monkeypatch.delenv(paths.ENV_CACHE_DIR)
    assert paths.cache_root() == Path.home() / ".cache" / "glaurung" / "sigs"


def test_offline_is_read_from_the_environment(monkeypatch):
    monkeypatch.delenv(paths.ENV_OFFLINE, raising=False)
    assert not paths.is_offline()
    for truthy in ("1", "true", "YES", "on"):
        monkeypatch.setenv(paths.ENV_OFFLINE, truthy)
        assert paths.is_offline()
    monkeypatch.setenv(paths.ENV_OFFLINE, "0")
    assert not paths.is_offline()


# --- the bundled artefacts themselves ----------------------------------------


def test_the_bundled_manifest_verifies_against_a_shipped_trusted_key():
    """A fresh offline install must be able to verify what it ships."""
    from glaurung.sigs import client, minisign

    keys = client.load_trusted_keys()
    assert keys, "no trusted key ships"
    matched = minisign.verify_file(
        paths.bundled_manifest_path(), paths.bundled_signature_path(), keys
    )
    assert matched in keys


def test_every_bundled_blob_is_present_and_hashes_correctly():
    import hashlib

    bundled = manifest_mod.Manifest.read(paths.bundled_manifest_path())
    assert bundled.blobs
    for blob in bundled.blobs:
        path = paths.bundled_blob_dir() / blob.sha256
        assert path.is_file(), f"{blob.key} names {blob.sha256}, which is not shipped"
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == blob.sha256
        assert len(data) == blob.size_bytes
        # The bytes must be a signature library, not an accident of copying.
        payload = json.loads(data)
        assert "entries" in payload and "library" in payload


def test_no_orphan_files_sit_in_the_bundled_blob_directory():
    """Content-addressed means every file there is named by the manifest."""
    bundled = manifest_mod.Manifest.read(paths.bundled_manifest_path())
    named = {blob.sha256 for blob in bundled.blobs}
    on_disk = {p.name for p in paths.bundled_blob_dir().iterdir() if p.is_file()}
    assert on_disk == named


def test_the_demo_library_and_its_bundled_copy_are_the_same_bytes():
    """`glaurung-base.x86_64.flirt.json` is also a bundled blob, by digest.

    The Rust loader still resolves the named file; the client resolves the
    sha256-named copy. If they ever drift, one of the two is stale and nothing
    else would say so.
    """
    import hashlib

    named = DATA / "glaurung-base.x86_64.flirt.json"
    digest = hashlib.sha256(named.read_bytes()).hexdigest()
    assert (paths.bundled_blob_dir() / digest).is_file(), (
        "data/sigs/glaurung-base.x86_64.flirt.json has no content-addressed "
        "copy under data/sigs/base/; rebuild the bundled set"
    )
