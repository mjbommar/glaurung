"""The network signature-source harvester parses what the sources really send.

`python/glaurung/tools/harvest_sources.py` turns a matrix spec into signature
libraries by walking three distributions' own infrastructure. Almost all of the
ways that goes wrong are *parsing* failures against a shape nobody checked, and
a parsing failure here is silent: an unreadable `Depends` field resolves to no
C++ package and the cell simply has one fewer library in it, an unfollowed ld
script loses libm from every glibc cell, an 8-byte stub counted as a failure
turns a correct harvest red.

So every parser is tested against a **real captured response**, committed under
`tests/fixtures/sig_sources/` with its URL and capture date in the README
there. Nothing in this file is invented input:

* `snapshot-mr-binary-libc6-dev.json` and
  `snapshot-binfiles-libc6-dev-2.36-9.json` from snapshot.debian.org's `/mr/`
  API, the only endpoints its robots.txt permits a machine to walk.
* `launchpad-*.json` from `api.launchpad.net`.
* `alpine-APKINDEX-v3.21-x86_64.txt`, cut from the real 2.2 MB index.
* `debian-Packages-*.txt`, the real `Depends` graph around `g++` from two
  releases whose shape differs -- bookworm's `g++-12` reaches
  `libstdc++-12-dev` in one hop, trixie's `g++-14` needs two.
* `debian-bookworm-libm.a.ldscript` and `debian-bookworm-libpthread.a.stub`,
  copied byte for byte out of `libc6-dev 2.36-9+deb12u14`.

The manifests under `tests/fixtures/sig_sources/manifests/` are real output of
the harvest recorded in `docs/reference/signature-sources.md`, and they are
checked against the **same** schema `test_system_archive_harvest.py` applies to
the Docker harvester's, because the whole point of the two harvesters is that
they produce one catalogue.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
from pathlib import Path

import pytest

from glaurung.tools import harvest_sources as hs

from test_system_archive_harvest import (  # noqa: E402  (rootdir is on sys.path)
    ARCHIVE_SCHEMA,
    COMPILER_KEYS,
    IMAGE_KEYS,
    MANIFEST_SCHEMA,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "sig_sources"
MANIFESTS = FIXTURES / "manifests"
SPEC = ROOT / "tools" / "sig_matrix" / "base.toml"

#: Extra keys the network harvester adds to every archive row. The Docker
#: harvester does not have them because a package it found on a local
#: filesystem has no URL to re-fetch from; these are what make a network row
#: re-derivable by someone who was not there.
NETWORK_ARCHIVE_KEYS = frozenset(
    {
        "package_source_url",
        "package_sha1",
        "package_sha256",
        "package_filename",
        "package_size",
        "suite",
        "source_backend",
        "licence",
        "licence_expected",
        "licence_source",
        "outcome",
        "ar_members",
        "extracted_path",
        "variant",
    }
)


def _fixture(name: str) -> str:
    path = FIXTURES / name
    assert path.is_file(), f"missing fixture {path}"
    return path.read_text(encoding="utf-8")


def _manifests() -> list[Path]:
    return sorted(MANIFESTS.glob("*/*/manifest.json"))


# ---------------------------------------------------------------------------
# snapshot.debian.org
# ---------------------------------------------------------------------------


def test_snapshot_version_listing_parses():
    """`/mr/binary/<pkg>/` is how a package's whole history is enumerated."""
    versions = hs.parse_snapshot_versions(_fixture("snapshot-mr-binary-libc6-dev.json"))
    assert versions[0] == "2.44-1"
    assert "2.43-4" in versions
    assert len(versions) == len(set(versions)), "versions must be deduplicated"


def test_snapshot_binfiles_splits_the_architecture_out_of_the_filename():
    """The endpoint has no arch field; the arch is inside `name`.

    A harvester that does not split it fetches whichever of the fifteen
    architectures the dict happened to iterate first, which for a signature
    library is not a small error: an aarch64 `libc.a` keyed as amd64 matches
    nothing and looks like the matcher being broken.
    """
    rows = hs.parse_snapshot_binfiles(
        _fixture("snapshot-binfiles-libc6-dev-2.36-9.json")
    )
    by_arch = {row["arch"]: row for row in rows}
    assert "amd64" in by_arch and "arm64" in by_arch
    amd64 = by_arch["amd64"]
    assert amd64["sha1"] == "82bdd995c40d95372b69be64cda8abcb69de04da"
    assert amd64["size"] == 1898160
    assert amd64["name"] == "libc6-dev_2.36-9_amd64.deb"
    assert len(amd64["sha1"]) == 40
    # Order-stable, so two parses of the same body agree.
    assert rows == hs.parse_snapshot_binfiles(
        _fixture("snapshot-binfiles-libc6-dev-2.36-9.json")
    )


def test_snapshot_parsers_reject_a_body_that_is_not_theirs():
    """A 500 page or an HTML error must not parse as an empty result set."""
    for parser in (hs.parse_snapshot_versions, hs.parse_snapshot_binfiles):
        with pytest.raises(hs.HarvestError):
            parser("<html>503</html>")
        with pytest.raises(hs.HarvestError):
            parser('{"unrelated": 1}')


# ---------------------------------------------------------------------------
# Launchpad
# ---------------------------------------------------------------------------


def test_launchpad_publication_parses():
    rows = hs.parse_launchpad_published(
        _fixture("launchpad-getPublishedBinaries-libc6-dev-noble-amd64.json")
    )
    assert rows, "no entries parsed"
    first = rows[0]
    assert first["binary_package_name"] == "libc6-dev"
    assert first["binary_package_version"].startswith("2.39-0ubuntu8")
    assert first["source_package_name"] == "glibc"
    assert first["status"] == "Published"
    assert first["self_link"].startswith("https://api.launchpad.net/")


def test_launchpad_file_urls_parse():
    urls = hs.parse_launchpad_file_urls(
        _fixture("launchpad-binaryFileUrls-libc6-dev-noble-amd64.json")
    )
    assert len(urls) == 1
    assert urls[0].endswith("_amd64.deb")
    assert urls[0].startswith("https://launchpad.net/ubuntu/+archive/primary/+files/")


def test_launchpad_parsers_reject_a_body_that_is_not_theirs():
    with pytest.raises(hs.HarvestError):
        hs.parse_launchpad_published('{"no": "entries"}')
    with pytest.raises(hs.HarvestError):
        hs.parse_launchpad_file_urls('{"entries": []}')


# ---------------------------------------------------------------------------
# Alpine
# ---------------------------------------------------------------------------


def test_apkindex_parses_and_carries_licence_and_hash():
    """APKINDEX gives the licence and a content hash without a second request."""
    records = {
        r["P"]: r
        for r in hs.parse_apkindex(_fixture("alpine-APKINDEX-v3.21-x86_64.txt"))
    }
    assert {"g++", "musl-dev", "zlib-static", "libstdc++-dev"} <= set(records)
    musl = records["musl-dev"]
    assert musl["V"] == "1.2.5-r11"
    assert musl["L"] == "MIT"
    assert musl["A"] == "x86_64"
    assert records["zlib-static"]["L"] == "Zlib"


def test_apk_checksum_decodes_to_a_sha1():
    """`C:Q1<base64>` is a 20-byte SHA-1; anything else must not be guessed at."""
    records = {
        r["P"]: r
        for r in hs.parse_apkindex(_fixture("alpine-APKINDEX-v3.21-x86_64.txt"))
    }
    digest = hs.apk_checksum_to_sha1(records["musl-dev"]["C"])
    assert len(digest) == 40
    assert int(digest, 16) >= 0
    assert hs.apk_checksum_to_sha1("Q2abcdef") == ""
    assert hs.apk_checksum_to_sha1("") == ""
    assert hs.apk_checksum_to_sha1("Q1not-base64!!") == ""


def test_alpine_libstdcxx_resolves_through_the_gxx_dependency():
    """Alpine spells it `libstdc++-dev`, and `g++` is what says so."""
    records = {
        r["P"]: r
        for r in hs.parse_apkindex(_fixture("alpine-APKINDEX-v3.21-x86_64.txt"))
    }
    assert "libstdc++-dev=" in records["g++"]["D"]


# ---------------------------------------------------------------------------
# Debian control format and the g++ dependency walk
# ---------------------------------------------------------------------------


def test_deb822_folds_continuation_lines():
    stanzas = hs.parse_deb822(_fixture("debian-Packages-bookworm-amd64.txt"))
    by_name = hs.index_deb822(stanzas)
    assert "libc6-dev" in by_name
    assert by_name["libc6-dev"]["Version"].startswith("2.36-9")
    assert len(by_name["libc6-dev"]["SHA256"]) == 64
    assert by_name["libc6-dev"]["Filename"].startswith("pool/")


@pytest.mark.parametrize(
    ("fixture", "expected", "hops"),
    [
        ("debian-Packages-bookworm-amd64.txt", "libstdc++-12-dev", 2),
        ("debian-Packages-trixie-amd64.txt", "libstdc++-14-dev", 3),
    ],
)
def test_libstdcxx_resolution_walks_the_real_depends_graph(
    fixture: str, expected: str, hops: int
):
    """The edge is transitive, and the number of hops is not the same everywhere.

    bookworm: `g++ -> g++-12 -> libstdc++-12-dev`.
    trixie:   `g++ -> g++-14 -> g++-14-x86-64-linux-gnu -> libstdc++-14-dev`.

    A one-hop resolver gets bookworm right and reports "no libstdc++-N-dev" for
    trixie, noble and resolute -- three of the seven releases in `base`, failing
    in a way that reads like the package having been renamed rather than like a
    bug here.
    """
    index = hs.index_deb822(hs.parse_deb822(_fixture(fixture)))
    name, evidence = hs._resolve_libstdcxx_dev(index)
    assert name == expected, evidence
    assert evidence.startswith("g++ ->")
    assert evidence.count("->") == hops, evidence


def test_libstdcxx_resolution_reports_why_it_failed():
    """An empty index must produce an explanation, not a silent empty name."""
    name, evidence = hs._resolve_libstdcxx_dev({})
    assert name == ""
    assert "g++" in evidence


# ---------------------------------------------------------------------------
# The measured archive traps
# ---------------------------------------------------------------------------


def test_ld_script_from_a_real_glibc_is_parsed():
    """glibc's `libm.a` is a script, and its paths are absolute."""
    names = hs.parse_ld_script(_fixture("debian-bookworm-libm.a.ldscript"))
    assert names == [
        "/usr/lib/x86_64-linux-gnu/libm-2.36.a",
        "/usr/lib/x86_64-linux-gnu/libmvec.a",
    ]
    assert hs.parse_ld_script("not a script") == []


def test_ld_script_paths_are_rerooted_at_the_extraction_root(tmp_path: Path):
    """An absolute path in a script describes the installed system, not the tarball.

    Following it literally reaches the *host's* glibc when the host has one --
    a wrong answer that succeeds, which is worse than one that fails. Nothing
    outside the extraction root may ever be returned.
    """
    root = tmp_path / "root"
    lib = root / "usr" / "lib" / "x86_64-linux-gnu"
    lib.mkdir(parents=True)
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    assert real.is_file(), real
    (lib / "libm-2.36.a").write_bytes(real.read_bytes())
    script = lib / "libm.a"
    script.write_text(_fixture("debian-bookworm-libm.a.ldscript"))

    resolved = hs.resolve_script_target(
        "/usr/lib/x86_64-linux-gnu/libm-2.36.a", script=script, root=root
    )
    assert resolved == lib / "libm-2.36.a"

    # libmvec.a is named by the script but absent from this package: None, not
    # the host's copy.
    assert (
        hs.resolve_script_target(
            "/usr/lib/x86_64-linux-gnu/libmvec.a", script=script, root=root
        )
        is None
    )
    # And an escape attempt stays inside.
    assert (
        hs.resolve_script_target("../../../../etc/passwd", script=script, root=root)
        is None
    )


def test_classify_archive_names_every_measured_outcome(tmp_path: Path):
    """Five outcomes, four of them files that are not what their name says."""
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    outcome, members = hs.classify_archive(real)
    assert outcome == hs.OUTCOME_ARCHIVE
    assert members > 0

    stub = FIXTURES / "debian-bookworm-libpthread.a.stub"
    assert stub.stat().st_size == 8, "the stub is exactly the ar magic"
    assert hs.classify_archive(stub) == (hs.OUTCOME_EMPTY_STUB, 0)

    script = FIXTURES / "debian-bookworm-libm.a.ldscript"
    assert hs.classify_archive(script) == (hs.OUTCOME_LD_SCRIPT, 0)

    thin = tmp_path / "libthin.a"
    thin.write_bytes(hs.AR_THIN_MAGIC + b"junk")
    assert hs.classify_archive(thin) == (hs.OUTCOME_THIN, 0)

    bare = tmp_path / "libmcheck.a"
    bare.write_bytes(b"\x7fELF" + b"\x00" * 200)
    assert hs.classify_archive(bare) == (hs.OUTCOME_NOT_ARCHIVE, 0)

    assert hs.classify_archive(tmp_path / "absent.a") == (hs.OUTCOME_NOT_ARCHIVE, 0)


def test_ar_members_are_enumerated_from_a_real_archive():
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    members = list(hs.iter_ar_members(real.read_bytes()))
    assert members, "no members read"
    assert all(name and not name.startswith("/") for name, _ in members)
    assert all(body[:4] == b"\x7fELF" for _, body in members)
    # The symbol index and the long-name table are not members.
    assert not any(name in ("/", "//", "/SYM64/") for name, _ in members)


def test_iter_ar_members_stops_on_a_truncated_archive():
    """A partial read is a fact about the file, not an exception."""
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    data = real.read_bytes()
    whole = list(hs.iter_ar_members(data))
    truncated = list(hs.iter_ar_members(data[: len(data) // 2]))
    assert len(truncated) < len(whole)
    assert list(hs.iter_ar_members(b"not an archive")) == []


def test_elf_comment_is_read_when_present_and_empty_when_not():
    """Alpine stamps `.comment`; Debian strips it from static-library objects."""
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    comments = {
        hs.elf_comment(body) for _name, body in hs.iter_ar_members(real.read_bytes())
    }
    # Whatever this box's own toolchain stamped, it must not crash and must not
    # invent a string for a non-ELF.
    assert all(isinstance(c, str) for c in comments)
    assert hs.elf_comment(b"") == ""
    assert hs.elf_comment(b"MZ" + b"\x00" * 200) == ""


def test_compiler_tag_records_which_rung_of_the_ladder_answered():
    """ "We read it" and "we assumed it" are different claims and are labelled."""
    assert hs.compiler_tag("GCC: (Alpine 14.2.0) 14.2.0", "gcc-14") == (
        "gcc-14.2.0",
        "comment-section",
    )
    assert hs.compiler_tag("", "gcc-12", built_using="gcc-12 (= 12.2.0-14)") == (
        "gcc-12.2.0",
        "built-using",
    )
    assert hs.compiler_tag("", "gcc-12", libstdcxx_version="12.2.0-14+deb12u1") == (
        "gcc-12.2.0",
        "libstdcxx-package-version",
    )
    assert hs.compiler_tag("", "gcc-15") == ("gcc-15", "distro-default")


def test_variant_and_triplet_conventions():
    """The variant is part of the key, so its spelling is a contract."""
    assert hs.variant_string("debian", "bookworm", "gcc-12.2.0") == (
        "debian-bookworm-gcc-12.2.0"
    )
    assert hs.triplet_for("debian", "amd64") == "x86_64-linux-gnu"
    assert hs.triplet_for("ubuntu", "arm64") == "aarch64-linux-gnu"
    assert hs.triplet_for("alpine", "x86_64") == "x86_64-linux-musl"
    assert hs.triplet_for("alpine", "aarch64") == "aarch64-linux-musl"
    assert hs.triplet_for("fedora", "amd64") == "unknown"
    assert hs.arch_for_triplet("aarch64-linux-musl") == "aarch64"
    assert hs.arch_for_triplet("nonesuch-linux-gnu") == "unknown"


def test_discover_archives_walks_a_tree_and_follows_its_script(tmp_path: Path):
    """The walk is a walk, not an allowlist: `libm-2.36.a` is not a known name."""
    root = tmp_path / "root"
    lib = root / "usr" / "lib" / "x86_64-linux-gnu"
    lib.mkdir(parents=True)
    real = ROOT / "samples/binaries/platforms/linux/amd64/libraries/static/libmathlib.a"
    (lib / "libm-2.36.a").write_bytes(real.read_bytes())
    (lib / "libm.a").write_text(_fixture("debian-bookworm-libm.a.ldscript"))
    (lib / "libpthread.a").write_bytes(
        (FIXTURES / "debian-bookworm-libpthread.a.stub").read_bytes()
    )

    findings = {f.path.name: f for f in hs.discover_archives(root)}
    assert findings["libm-2.36.a"].outcome == hs.OUTCOME_ARCHIVE
    assert findings["libm-2.36.a"].members > 0
    assert findings["libm.a"].outcome == hs.OUTCOME_LD_SCRIPT
    assert findings["libpthread.a"].outcome == hs.OUTCOME_EMPTY_STUB
    # Deterministic ordering, so two harvests of the same tree diff to nothing.
    assert [f.path for f in hs.discover_archives(root)] == [
        f.path for f in hs.discover_archives(root)
    ]


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------


def test_base_spec_loads_and_declares_the_matrix():
    document = hs.load_spec(SPEC)
    targets = hs.targets_of(document)
    keys = {f"{t.distro}-{t.release}" for t in targets}
    assert keys == {
        "debian-bookworm",
        "debian-trixie",
        "ubuntu-jammy",
        "ubuntu-noble",
        "ubuntu-resolute",
        "alpine-v3.20",
        "alpine-v3.21",
    }
    for target in targets:
        assert len(target.arches) == 2, target.release
        assert target.packages, target.release
        assert all(hs.triplet_for(target.distro, a) != "unknown" for a in target.arches)
        assert target.default_compiler.startswith("gcc-")
    # Fedora is out of scope for this lane, and says so rather than being absent.
    assert "fedora" in document["out_of_scope"]


def test_base_spec_declares_a_licence_for_every_package():
    document = hs.load_spec(SPEC)
    declared = set(document["licences"])
    for target in hs.targets_of(document):
        for package in target.packages:
            assert package in declared, f"{package} has no licence in the spec"


def test_load_spec_rejects_a_malformed_spec(tmp_path: Path):
    bad = tmp_path / "bad.toml"
    bad.write_text('schema_version = "1"\nname = "x"\n')
    with pytest.raises(hs.HarvestError):
        hs.load_spec(bad)
    bad.write_text(
        'schema_version = "1"\nname = "x"\n[[target]]\nbackend = "nonesuch"\n'
        'distro = "d"\nrelease = "r"\narches = ["amd64"]\npackages = ["p"]\n'
    )
    with pytest.raises(hs.HarvestError):
        hs.load_spec(bad)


# ---------------------------------------------------------------------------
# The manifests, against the Docker harvester's own schema
# ---------------------------------------------------------------------------


def test_network_manifest_fixtures_exist():
    assert _manifests(), f"no manifests under {MANIFESTS}"


@pytest.mark.parametrize("path", _manifests(), ids=lambda p: p.parent.parent.name)
def test_network_manifest_matches_the_shared_schema(path: Path):
    """One catalogue, two producers: the same schema has to hold for both.

    `harvest_system_archives.py --index-root` builds a single `index.json` over
    the Docker harvester's trees and this one's, and
    `tools/build_signature_set.py` reads that index without knowing which
    harvester wrote a row. The moment the shapes diverge, half the catalogue
    stops building.
    """
    manifest = json.loads(path.read_text())
    for key, kind in MANIFEST_SCHEMA.items():
        assert key in manifest, f"{path}: missing {key}"
        assert isinstance(manifest[key], kind), f"{path}: {key} is not {kind}"
    assert manifest["schema_version"] == "1"
    assert IMAGE_KEYS <= set(manifest["image"])
    assert COMPILER_KEYS <= set(manifest["compiler"])
    assert manifest["triplet"] == path.parent.name
    assert manifest["archives"], f"{path}: harvested nothing"

    for row in manifest["archives"]:
        for key, kind in ARCHIVE_SCHEMA.items():
            assert key in row, f"{path}: {row.get('name')} missing {key}"
            assert isinstance(row[key], kind), f"{path}: {row['name']}.{key} bad type"
        assert NETWORK_ARCHIVE_KEYS <= set(row), (
            f"{path}: {row['name']} missing {NETWORK_ARCHIVE_KEYS - set(row)}"
        )
        assert len(row["sha256"]) == 64
        assert row["size"] > 0
        assert row["ar_members"] > 0, "an archive row with no members is a stub"
        assert row["outcome"] == hs.OUTCOME_ARCHIVE
        assert row["relative_path"] == f"lib/{row['name']}"
        assert row["triplet"] == manifest["triplet"]


@pytest.mark.parametrize("path", _manifests(), ids=lambda p: p.parent.parent.name)
def test_network_manifest_can_be_refetched(path: Path):
    """Provenance is only provenance if it is enough to get the bytes back.

    Every archive names a package, a version, a suite, a URL and at least one
    content hash. This is the whole legal position in one assertion: we ship
    signatures and names, never the archives, and anyone who wants to check us
    can re-fetch and re-derive.
    """
    manifest = json.loads(path.read_text())
    for row in manifest["archives"]:
        assert row["package"] and row["package"] != "unknown", row["name"]
        assert row["package_version"] and row["package_version"] != "unknown"
        assert row["suite"], row["name"]
        assert row["package_source_url"].startswith("http"), row["name"]
        assert row["package_sha1"] or row["package_sha256"], (
            f"{row['name']}: no content hash for {row['package_source_url']}"
        )
        assert row["variant"].startswith(f"{manifest['image']['os_id']}-")


@pytest.mark.parametrize("path", _manifests(), ids=lambda p: p.parent.parent.name)
def test_network_manifest_records_the_non_archive_outcomes(path: Path):
    """An empty stub is a correct result, and has to be visible as one.

    Five of glibc's archives have been eight bytes since 2.34 merged them into
    libc, and every Alpine archive but `libc.a` is one too. A harvest that
    reports only what it kept looks like it lost them.
    """
    manifest = json.loads(path.read_text())
    totals = manifest["totals"]
    assert totals["archives"] == len(manifest["archives"])
    assert totals["bytes"] == sum(r["size"] for r in manifest["archives"])
    assert totals["outcome_archive"] == totals["archives"]
    assert totals["outcome_empty_stub"] > 0, "no stubs seen; the walk missed them"
    assert manifest["outcomes"], "outcomes must list every candidate, not just the kept"
    assert len(manifest["outcomes"]) >= len(manifest["archives"])
    for row in manifest["outcomes"]:
        assert row["outcome"] in {
            hs.OUTCOME_ARCHIVE,
            hs.OUTCOME_EMPTY_STUB,
            hs.OUTCOME_LD_SCRIPT,
            hs.OUTCOME_THIN,
            hs.OUTCOME_NOT_ARCHIVE,
        }


@pytest.mark.parametrize("path", _manifests(), ids=lambda p: p.parent.parent.name)
def test_network_manifest_json_is_canonical(path: Path):
    """Sorted keys, two-space indent, trailing newline: a re-harvest diffs cleanly."""
    text = path.read_text()
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


def test_docker_index_builder_accepts_a_network_cell(tmp_path: Path):
    """`--index-root` must catalogue a network cell as an image, not skip it."""
    import importlib.util

    harvester = ROOT / "samples" / "docker" / "harvest_system_archives.py"
    spec = importlib.util.spec_from_file_location("harvest_system_archives", harvester)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    root = tmp_path / "system-libs"
    root.mkdir()
    for cell in sorted(MANIFESTS.iterdir()):
        if cell.is_dir():
            shutil.copytree(cell, root / cell.name)

    index = module.build_index(root)
    assert index["images"], "the network cells were not recognised as harvests"
    assert index["totals"]["archives"] > 0
    for image in index["images"]:
        assert (root / image["index"]).is_file()


def test_manifest_and_index_agree(tmp_path: Path):
    """The per-cell `index.json` is not allowed to drift from its manifest."""
    for manifest_path in _manifests():
        index_path = manifest_path.parent.parent / "index.json"
        assert index_path.is_file(), index_path
        manifest = json.loads(manifest_path.read_text())
        index = json.loads(index_path.read_text())
        assert index["schema_version"] == manifest["schema_version"]
        assert index["image"] == manifest["image"]
        assert len(index["triplets"]) == 1
        triplet = index["triplets"][0]
        assert triplet["triplet"] == manifest["triplet"]
        assert triplet["archives"] == manifest["archives"]
        assert triplet["manifest"] == f"{manifest['triplet']}/manifest.json"


# ---------------------------------------------------------------------------
# Determinism, and the one test that touches the network
# ---------------------------------------------------------------------------


def test_write_json_is_deterministic(tmp_path: Path):
    payload = {"b": 2, "a": {"d": 4, "c": 3}}
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    hs.write_json(first, payload)
    hs.write_json(second, {"a": {"c": 3, "d": 4}, "b": 2})
    assert first.read_text() == second.read_text()
    assert first.read_text().endswith("}\n")


def test_fetcher_refuses_to_exceed_its_cap(tmp_path: Path):
    """The download budget is a hard stop, checked before the request goes out."""
    fetcher = hs.Fetcher(cache_root=tmp_path, delay=0.0, cap_bytes=10)
    fetcher.downloaded = 10
    with pytest.raises(hs.DownloadCapExceeded):
        fetcher.get("https://example.invalid/never-requested")
    assert fetcher.requests == 0, "the cap must be checked before the request"


def test_fetcher_user_agent_names_the_project_and_a_contact():
    """An anonymous bulk fetcher is indistinguishable from an abusive one."""
    assert "glaurung" in hs.USER_AGENT
    assert hs.CONTACT_URL in hs.USER_AGENT
    assert hs.DEFAULT_DELAY_SECONDS > 0
    assert hs.DEFAULT_BYTE_CAP == 6 * 1024**3


def test_snapshot_backend_requests_only_robots_permitted_endpoints():
    """snapshot.debian.org disallows `/archive/*`, `/binary/*` and `/package/*`.

    `/mr/binary/...` is *not* `/binary/...`; the distinction is the whole reason
    the machine-readable API exists, and getting it wrong is the difference
    between a permitted client and a banned one.
    """
    fetcher = hs.Fetcher(cache_root=Path("/nonexistent"), delay=0.0)
    backend = hs.DebianBackend(fetcher)
    assert backend.snapshot == "https://snapshot.debian.org"
    urls = [
        f"{backend.snapshot}/mr/binary/libc6-dev/",
        f"{backend.snapshot}/mr/binary/libc6-dev/2.36-9/binfiles",
        f"{backend.snapshot}/file/82bdd995c40d95372b69be64cda8abcb69de04da",
    ]
    for url in urls:
        tail = url[len(backend.snapshot) :]
        assert tail.startswith(("/mr/", "/file/")), url


def test_ubuntu_mirror_selection_covers_ports_and_eol():
    """arm64 is on ports, an Obsolete series is on old-releases, both silently."""
    fetcher = hs.Fetcher(cache_root=Path("/nonexistent"), delay=0.0)
    backend = hs.UbuntuBackend(fetcher)
    backend._series_status = {"noble": "Supported", "mantic": "Obsolete"}
    assert backend.mirror_for("noble", "amd64") == backend.archive_mirror
    assert backend.mirror_for("noble", "arm64") == backend.ports_mirror
    assert backend.mirror_for("mantic", "amd64") == backend.old_archive_mirror
    assert backend.mirror_for("mantic", "arm64") == backend.old_ports_mirror
    assert backend.POCKETS == ("", "-updates", "-security")


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("GLAURUNG_SIG_NETWORK") != "1",
    reason="network test; set GLAURUNG_SIG_NETWORK=1 to run it",
)
def test_network_fetch_of_one_small_package(tmp_path: Path):
    """End to end over the real Alpine CDN, on the smallest package in `base`.

    `zlib-static` is 60 KB, which is the whole point of choosing it: this test
    proves the fetch, the content-addressed cache, the concatenated-gzip
    extraction and the archive walk against a live source without pulling a
    5 MB glibc every time someone runs the suite with the variable set.
    """
    fetcher = hs.Fetcher(cache_root=tmp_path / "cache", delay=0.5, cap_bytes=4 << 20)
    backend = hs.AlpineBackend(fetcher)
    target = next(
        t
        for t in hs.targets_of(hs.load_spec(SPEC))
        if t.backend == "alpine" and t.release == "v3.21"
    )
    refs = [r for r in backend.resolve(target, "x86_64") if r.package == "zlib-static"]
    assert len(refs) == 1
    ref = refs[0]
    assert ref.licence == "Zlib"
    assert len(ref.sha1) == 40

    path, digest, from_cache = backend.fetch(ref)
    assert path.is_file() and len(digest) == 64 and not from_cache
    # The cache is content-addressed, so the second fetch issues no request.
    before = fetcher.requests
    _path2, digest2, from_cache2 = backend.fetch(ref)
    assert digest2 == digest and from_cache2 and fetcher.requests == before

    extracted = tmp_path / "x"
    backend.extract(path, extracted)
    findings = {f.path.name: f for f in hs.discover_archives(extracted)}
    assert "libz.a" in findings
    assert findings["libz.a"].outcome == hs.OUTCOME_ARCHIVE
    assert findings["libz.a"].members > 0


@pytest.mark.slow
@pytest.mark.skipif(
    os.environ.get("GLAURUNG_SIG_NETWORK") != "1",
    reason="network test; set GLAURUNG_SIG_NETWORK=1 to run it",
)
def test_a_warm_rerun_is_byte_identical_apart_from_timestamps(tmp_path: Path):
    """The manifest describes the cell, not the run that produced it.

    A field that records something about *this execution* -- how long it took,
    whether a package came off disk -- makes a warm re-run diff against a cold
    one on every row, and then nobody can review the diff that matters. The
    two timestamps are the deliberate exception and are the only one.
    """
    fetcher = hs.Fetcher(
        cache_root=tmp_path / "cache",
        delay=0.5,
        cap_bytes=64 << 20,
        reuse_indexes=True,
    )
    backend = hs.AlpineBackend(fetcher)
    spec = hs.load_spec(SPEC)
    target = next(
        t for t in hs.targets_of(spec) if t.backend == "alpine" and t.release == "v3.21"
    )
    # One package, so the test costs 60 KB rather than 19 MB.
    target = dataclasses.replace(target, packages=("zlib-static",))

    out = tmp_path / "out"
    work = tmp_path / "work"
    for _ in range(2):
        hs.harvest_cell(
            backend,
            target,
            "x86_64",
            out,
            work,
            expected_licences=dict(spec.get("licences", {})),
        )
        manifest = out / "alpine-v3.21-x86_64" / "x86_64-linux-musl" / "manifest.json"
        (tmp_path / f"seen-{_}.json").write_text(manifest.read_text())

    first = json.loads((tmp_path / "seen-0.json").read_text())
    second = json.loads((tmp_path / "seen-1.json").read_text())
    for payload in (first, second):
        assert payload.pop("generated_utc")
        assert payload["source"].pop("fetched_utc")
    assert first == second
    # And the second pass issued no package request.
    assert fetcher.served_from_cache > 0
