"""The system-archive harvest emits a valid, deterministic manifest.

`samples/docker/harvest_system_archives.py` runs inside a `samples/docker`
build image and exports the distribution's own static archives -- the
*unlinked* `.a` members a FLIRT-style signature library has to be built from --
together with the `dpkg` provenance that keys the library:
`(package, package version, variant, arch)`.

Two properties are worth a gate, and neither is about the archives themselves:

1. **The manifest says what it must.** A harvest that copied bytes out but
   recorded `"unknown"` for the owning package produces a signature library
   keyed on nothing, which is worse than no library: the key is what tells a
   later match which build it came from.
2. **The JSON is canonical.** `index.json` and every `manifest.json` are
   written with sorted keys and a trailing newline, so re-running the harvest
   over an unchanged image produces a zero-line diff. Without that, the file
   cannot be reviewed and "did the image change?" is unanswerable.

The fixtures under `python/tests/fixtures/system_libs/` are the *real*
manifests from the first harvest of the `linux/amd64` image: 8 triplets, 174
archives, glibc and musl and MinGW-w64 and four cross libcs. Only that one
image, because the `windows/amd64` harvest repeats four of the same triplets
and would double the bytes without widening the schema coverage. They carry no
archive content -- only names, sizes, hashes and package provenance -- so they
are a quarter of a megabyte rather than the 200 MB the archives themselves
occupy.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARVESTER = ROOT / "samples" / "docker" / "harvest_system_archives.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "system_libs"

#: Every key a manifest must carry, with the type it must have.
MANIFEST_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "schema_version": str,
    "generated_utc": str,
    "triplet": str,
    "arch": str,
    "image": dict,
    "compiler": dict,
    "compiler_note": str,
    "archives": list,
    "totals": dict,
}

#: Every key an archive row must carry.
ARCHIVE_SCHEMA: dict[str, type | tuple[type, ...]] = {
    "name": str,
    "relative_path": str,
    "source_path": str,
    "resolved_from": str,
    "size": int,
    "sha256": str,
    "package": str,
    "package_version": str,
    "package_architecture": str,
    "triplet": str,
    "arch": str,
    "compiler": str,
    "compiler_driver": str,
}

IMAGE_KEYS = frozenset(
    {
        "name",
        "base",
        "os_id",
        "os_version_id",
        "target_os",
        "target_arch",
        "dpkg_architecture",
        "uname_machine",
    }
)

COMPILER_KEYS = frozenset({"driver", "path", "version", "package", "package_version"})


def _harvester():
    """Import the in-image harvester by path; it is not an installed module."""
    spec = importlib.util.spec_from_file_location("harvest_system_archives", HARVESTER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _manifests() -> list[Path]:
    return sorted(FIXTURES.glob("*/*/manifest.json"))


def _indexes() -> list[Path]:
    return sorted(FIXTURES.glob("*/index.json"))


def test_the_harvester_exists_and_imports():
    """The build scripts call it by path; a rename breaks every image."""
    assert HARVESTER.is_file(), HARVESTER
    mod = _harvester()
    assert callable(mod.harvest)
    assert callable(mod.build_index)


def test_fixture_manifests_are_present():
    """Guards against the fixture tree being emptied without the tests noticing."""
    assert _manifests(), f"no manifests under {FIXTURES}"
    assert _indexes(), f"no per-image index.json under {FIXTURES}"


@pytest.mark.parametrize("manifest_path", _manifests(), ids=lambda p: p.parent.name)
def test_manifest_matches_schema(manifest_path: Path):
    """Every required key is present, with the right type."""
    manifest = json.loads(manifest_path.read_text())
    for key, kind in MANIFEST_SCHEMA.items():
        assert key in manifest, f"{manifest_path}: missing {key}"
        assert isinstance(manifest[key], kind), f"{manifest_path}: {key} is not {kind}"

    assert manifest["schema_version"] == "1"
    assert IMAGE_KEYS <= set(manifest["image"])
    assert COMPILER_KEYS <= set(manifest["compiler"])
    # The manifest lives in the directory named after its own triplet.
    assert manifest["triplet"] == manifest_path.parent.name

    assert manifest["archives"], f"{manifest_path}: harvested nothing"
    for row in manifest["archives"]:
        for key, kind in ARCHIVE_SCHEMA.items():
            assert key in row, f"{manifest_path}: {row.get('name')} missing {key}"
            assert isinstance(row[key], kind), (
                f"{manifest_path}: {row.get('name')}.{key} is not {kind}"
            )
        assert len(row["sha256"]) == 64
        assert row["size"] > 0
        assert row["relative_path"] == f"lib/{row['name']}"
        assert row["triplet"] == manifest["triplet"]

    totals = manifest["totals"]
    assert totals["archives"] == len(manifest["archives"])
    assert totals["bytes"] == sum(r["size"] for r in manifest["archives"])


@pytest.mark.parametrize("manifest_path", _manifests(), ids=lambda p: p.parent.name)
def test_manifest_records_real_package_provenance(manifest_path: Path):
    """A manifest of `unknown` packages keys a signature library on nothing."""
    manifest = json.loads(manifest_path.read_text())
    unknown = [r["name"] for r in manifest["archives"] if r["package"] == "unknown"]
    assert not unknown, f"{manifest_path}: no dpkg owner for {unknown}"
    unversioned = [
        r["name"] for r in manifest["archives"] if r["package_version"] == "unknown"
    ]
    assert not unversioned, f"{manifest_path}: no package version for {unversioned}"


@pytest.mark.parametrize(
    "path", _manifests() + _indexes(), ids=lambda p: f"{p.parent.name}/{p.name}"
)
def test_json_is_canonical(path: Path):
    """Sorted keys, two-space indent, trailing newline: a rebuild diffs cleanly."""
    text = path.read_text()
    expected = json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
    assert text == expected, f"{path} is not canonical JSON; rewrite with write_json"


def test_build_index_is_deterministic(tmp_path: Path):
    """Two runs over the same tree produce byte-identical, canonical output."""
    mod = _harvester()
    root = tmp_path / "system-libs"
    shutil.copytree(FIXTURES, root)

    mod.build_index(root)
    first = (root / "index.json").read_text()
    mod.build_index(root)
    second = (root / "index.json").read_text()

    assert first == second
    assert first == json.dumps(json.loads(first), indent=2, sort_keys=True) + "\n"

    index = json.loads(first)
    assert index["images"], "top-level index found no image harvests"
    assert [i["image"] for i in index["images"]] == sorted(
        i["image"] for i in index["images"]
    )
    assert index["totals"]["archives"] > 0
    assert index["totals"]["bytes"] > 0


def test_build_index_ignores_a_neighbour_that_is_not_a_harvest(tmp_path: Path):
    """The harvest root is a cache directory, and cache directories get shared.

    The derived signature set lands in `sigs/` inside the same root, and other
    lanes of the signature-library program have written a `warp/` beside it,
    each with an `index.json` of its own shape. Both were picked up as
    "images" until the check became the schema rather than the filename.
    """
    mod = _harvester()
    root = tmp_path / "system-libs"
    shutil.copytree(FIXTURES, root)
    real = [p.parent.name for p in sorted(root.glob("*/index.json"))]

    (root / "sigs").mkdir()
    (root / "sigs" / "index.json").write_text(
        json.dumps({"schema_version": "1", "libraries": [], "totals": {}})
    )
    (root / "not-json").mkdir()
    (root / "not-json" / "index.json").write_text("this is not json\n")

    index = mod.build_index(root)
    assert [i["image"] for i in index["images"]] == real


def test_top_level_index_paths_point_into_the_tree(tmp_path: Path):
    """Every path in the index is relative to the harvest root and resolvable."""
    mod = _harvester()
    root = tmp_path / "system-libs"
    shutil.copytree(FIXTURES, root)
    index = mod.build_index(root)

    for image in index["images"]:
        assert (root / image["index"]).is_file()
        for triplet in image["triplets"]:
            for archive in triplet["archives"]:
                # The archives themselves are not committed, but the path has
                # to be the documented <image>/<triplet>/lib/<name> shape.
                assert archive["path"] == (
                    f"{image['image']}/{triplet['triplet']}/lib/{archive['name']}"
                )


def test_triplet_is_derived_from_the_path():
    """Multilib subdirectories resolve to the ABI they hold, not their parent."""
    mod = _harvester()
    cases = {
        "/usr/lib/x86_64-linux-gnu/libc.a": "x86_64-linux-gnu",
        "/usr/lib/gcc/x86_64-linux-gnu/11/libstdc++.a": "x86_64-linux-gnu",
        "/usr/lib/gcc/x86_64-linux-gnu/11/32/libstdc++.a": "i386-linux-gnu",
        "/usr/lib32/libc.a": "i386-linux-gnu",
        "/usr/libx32/libc.a": "x86_64-linux-gnux32",
        "/usr/aarch64-linux-gnu/lib/libc.a": "aarch64-linux-gnu",
        "/usr/lib/gcc-cross/riscv64-linux-gnu/11/libgcc.a": "riscv64-linux-gnu",
        "/usr/x86_64-w64-mingw32/lib/libmingwex.a": "x86_64-w64-mingw32",
        "/usr/lib/x86_64-linux-musl/libc.a": "x86_64-linux-musl",
    }
    for path, expected in cases.items():
        assert mod.triplet_for_path(Path(path)) == expected, path


def test_arch_tag_for_triplet():
    """The `--arch` tag a signature library is keyed by."""
    mod = _harvester()
    assert mod.arch_for_triplet("x86_64-linux-gnu") == "x86_64"
    assert mod.arch_for_triplet("x86_64-linux-gnux32") == "x86_64"
    assert mod.arch_for_triplet("i686-w64-mingw32") == "i386"
    assert mod.arch_for_triplet("i386-linux-gnu") == "i386"
    assert mod.arch_for_triplet("aarch64-linux-gnu") == "aarch64"
    assert mod.arch_for_triplet("arm-linux-gnueabihf") == "arm"
    assert mod.arch_for_triplet("riscv64-linux-gnu") == "riscv64"
    assert mod.arch_for_triplet("nonesuch-linux-gnu") == "unknown"


def test_resolve_archive_accepts_an_ar_archive_and_rejects_a_non_archive():
    """Not every file named `lib*.a` is an archive; two exceptions matter.

    glibc ships `libm.a` as a GNU ld script naming the versioned
    `libm-2.35.a`, and `libmcheck.a` is a single relocatable object wearing an
    archive's name. Both were found by running the harvest: before the script
    resolved them, libm was missing from every triplet and the builder reported
    `not an ar archive` thirteen times.
    """
    mod = _harvester()
    archive = (
        ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    )
    assert archive.is_file(), archive
    assert archive.read_bytes()[:8] == mod.AR_MAGIC
    assert mod.resolve_archive(archive) == [(archive, "")]

    # A real file that is not an archive and names no archives.
    assert mod.resolve_archive(HARVESTER) == []


def test_resolve_archive_follows_a_gnu_ld_script(tmp_path: Path):
    """A `GROUP ( ... )` script resolves to the archives it names.

    The script text is glibc's own, copied from
    `/usr/lib/x86_64-linux-gnu/libm.a` in the `linux/amd64` build image; the
    archive it points at is this repository's real `libmathlib.a`, so no byte
    here is invented.
    """
    mod = _harvester()
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    lib = tmp_path / "libmathlib-1.0.a"
    lib.write_bytes(real.read_bytes())
    script = tmp_path / "libmathlib.a"
    script.write_text(
        "/* GNU ld script\n*/\nOUTPUT_FORMAT(elf64-x86-64)\n"
        "GROUP ( libmathlib-1.0.a )\n"
    )

    assert mod.resolve_archive(script) == [(lib, str(script))]


def test_allowlist_has_no_duplicates():
    """A repeated basename would harvest and hash the same file twice."""
    mod = _harvester()
    names = list(mod.ARCHIVE_NAMES)
    assert len(names) == len(set(names))
