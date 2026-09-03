"""The fetch/cache/verify path, end to end, over a real HTTP server.

Every test here runs the *actual* publish tool against a directory of real
blob bytes, serves the result over `http://127.0.0.1`, and fetches it through
the same code a user runs. Nothing is mocked: a mocked transport cannot tell
you that range resume works, that a tampered blob is caught, or that a bad
partial file is deleted rather than resumed into a "successful" fetch.

The four defences each get a test that would pass if the defence were removed
only by accident:

* **tamper** -- a blob whose bytes were changed on the mirror,
* **downgrade** -- a correctly-signed manifest with a lower serial,
* **forgery** -- a manifest signed by a key that is not trusted,
* **offline** -- `GLAURUNG_SIGS_OFFLINE=1` reaching the bundled set and never
  the network.
"""

from __future__ import annotations

import functools
import hashlib
import http.server
import json
import subprocess
import sys
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from glaurung.sigs import client, minisign, paths
from glaurung.sigs.catalog import Catalog
from glaurung.sigs.manifest import Manifest

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / "tools" / "publish_signature_set.py"


# --- a real, tiny corpus -----------------------------------------------------


def _write_corpus(directory: Path, count: int = 3) -> Path:
    """Blob files shaped like the harvester's output, plus its index.

    Real JSON of the shape `build_flirt_library.py` emits, not opaque
    padding: the publish tool reads the index for provenance and the client
    stores whatever bytes it is given, so the only property that has to be
    real is that the files are distinct and non-trivial in size.
    """
    directory.mkdir(parents=True, exist_ok=True)
    records = []
    for i in range(count):
        name = f"lib{i}.flirt.json"
        payload = {
            "schema_version": "2",
            "arch": "x86_64",
            "prologue_len": 32,
            "library": {
                "name": f"lib{i}",
                "version": "1.0.0",
                "variant": "gcc-11-O2",
                "arch": "x86_64",
            },
            "entries": [
                {
                    "name": f"lib{i}_function_{j}",
                    "prologue_hex": f"{j:02x}" * 32,
                    "crc16": j,
                    "crc_len": 8,
                }
                for j in range(40 * (i + 1))
            ],
        }
        (directory / name).write_text(json.dumps(payload, indent=1), encoding="utf-8")
        records.append(
            {
                "key": f"host.x86_64-linux-gnu.lib{i}",
                "output": name,
                "library_name": f"lib{i}-dev",
                "library_version": "1.0.0",
                "variant": "gcc-11-O2",
                "arch": "x86_64",
                "triplet": "x86_64-linux-gnu",
                "image": "test",
                "archive": f"lib{i}.a",
                "archive_sha256": hashlib.sha256(name.encode()).hexdigest(),
                "unique_signatures": 40 * (i + 1),
            }
        )
    (directory / "index.json").write_text(
        json.dumps({"schema_version": 1, "libraries": records}), encoding="utf-8"
    )
    return directory


def _publish(
    corpus: Path,
    out: Path,
    key_path: Path,
    *,
    serial: int = 1,
    set_version: str = "2026.09.1",
    base_url: str = "http://127.0.0.1:0",
) -> Manifest:
    """Run tools/publish_signature_set.py for real, as a subprocess."""
    result = subprocess.run(
        [
            sys.executable,
            str(PUBLISH),
            "--blobs",
            str(corpus),
            "--set",
            "base",
            "--set-version",
            set_version,
            "--serial",
            str(serial),
            "--out",
            str(out),
            "--secret-key",
            str(key_path),
            "--generate-key",
            "--r2-base",
            base_url,
            "--hf-repo",
            "",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return Manifest.read(out / "manifest.json")


def _rewrite_urls(out: Path, base_url: str, key_path: Path) -> Manifest:
    """Point every blob at the live test server, then re-sign.

    The publish tool bakes real release URLs in, which is correct for a real
    release and useless for a test. Re-signing rather than skipping the
    signature is deliberate: the client must be exercised on a *validly
    signed* manifest, or the test would only ever prove the failure path.
    """
    manifest = Manifest.read(out / "manifest.json")
    rewritten = manifest.with_blobs(
        [
            replace(blob, urls=(f"{base_url}/blobs/{blob.sha256}",))
            for blob in manifest.blobs
        ]
    )
    path = rewritten.write(out / "manifest.json")
    minisign.sign_file(
        minisign.SecretKey.read(key_path),
        path,
        trusted_comment=rewritten.trusted_comment(),
    )
    return rewritten


class _RangeHandler(http.server.SimpleHTTPRequestHandler):
    """A static server that honours `Range`, and records what it served.

    `SimpleHTTPRequestHandler` does **not** implement range requests: it
    ignores the header and answers 200 with the whole body. Serving with it
    made the resume test pass for the wrong reason -- the client re-downloaded
    from zero every time and the assertion could not tell. `served` exists so
    the test can assert a 206 actually happened and that fewer bytes crossed
    the wire than the blob contains.
    """

    def __init__(self, *args, served=None, **kwargs):
        self.served = served if served is not None else []
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args) -> None:
        """Silence the per-request line; keep the test output readable."""
        return

    def do_GET(self):  # noqa: N802 - stdlib naming
        path = Path(self.translate_path(self.path))
        if not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        start, status = 0, 200
        header = self.headers.get("Range", "")
        if header.startswith("bytes="):
            spec = header[len("bytes=") :].split("-")[0]
            if spec.isdigit():
                start = int(spec)
                if start >= len(data):
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{len(data)}")
                    self.end_headers()
                    self.served.append((self.path, start, 0, 416))
                    return
                status = 206
        body = data[start:]
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        if status == 206:
            self.send_header(
                "Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}"
            )
        self.end_headers()
        self.wfile.write(body)
        self.served.append((self.path, start, len(body), status))


class _Servers:
    """Start localhost servers, and keep the shared request log.

    `log` holds `(path, range_start, bytes_sent, status)` per request, which
    is what lets the resume test assert a 206 actually happened rather than
    silently accepting a full re-download.
    """

    def __init__(self) -> None:
        self.servers: list[http.server.ThreadingHTTPServer] = []
        self.log: list[tuple[str, int, int, int]] = []

    def __call__(self, directory: Path) -> str:
        handler = functools.partial(
            _RangeHandler, directory=str(directory), served=self.log
        )
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{server.server_address[1]}"

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()


@pytest.fixture
def serve():
    """Serve directories over localhost HTTP for the duration of one test."""
    servers = _Servers()
    yield servers
    servers.close()


@pytest.fixture
def release(tmp_path, serve):
    """A published, signed, served release plus the key that signed it."""
    corpus = _write_corpus(tmp_path / "corpus")
    out = tmp_path / "release"
    key_path = tmp_path / "keys" / "signing.key"
    _publish(corpus, out, key_path)
    base_url = serve(out)
    manifest = _rewrite_urls(out, base_url, key_path)
    public = minisign.SecretKey.read(key_path).public_key()
    return {
        "out": out,
        "url": f"{base_url}/manifest.json",
        "manifest": manifest,
        "keys": [public],
        "key_path": key_path,
        "base_url": base_url,
        "log": serve.log,
    }


# --- the happy path ----------------------------------------------------------


def test_fetch_downloads_verifies_and_caches_every_blob(release, tmp_path):
    root = tmp_path / "cache"
    result = client.fetch(
        "base", release["url"], root=root, keys=release["keys"], offline=False
    )

    assert len(result.downloaded) == len(release["manifest"].blobs)
    assert result.warnings == []
    assert result.verified_by == release["keys"][0].key_id_hex

    for blob in release["manifest"].blobs:
        cached = root / blob.sha256
        assert cached.is_file(), blob.key
        assert hashlib.sha256(cached.read_bytes()).hexdigest() == blob.sha256

    catalog = Catalog.load(root)
    assert catalog.serial == release["manifest"].serial
    assert set(catalog.entries) == {b.key for b in release["manifest"].blobs}
    assert catalog.verified_by_key_id == release["keys"][0].key_id_hex

    # The cache is now self-describing: `resolve` answers without the network.
    key = release["manifest"].blobs[0].key
    assert client.resolve(key, root) == root / release["manifest"].blobs[0].sha256


def test_a_second_fetch_downloads_nothing(release, tmp_path):
    root = tmp_path / "cache"
    client.fetch("base", release["url"], root=root, keys=release["keys"], offline=False)
    again = client.fetch(
        "base", release["url"], root=root, keys=release["keys"], offline=False
    )
    assert again.downloaded == []
    assert len(again.already_cached) == len(release["manifest"].blobs)
    assert again.bytes_downloaded == 0


def test_only_selects_a_subset(release, tmp_path):
    root = tmp_path / "cache"
    wanted = release["manifest"].blobs[0].key
    result = client.fetch(
        "base",
        release["url"],
        root=root,
        keys=release["keys"],
        offline=False,
        only=[wanted],
    )
    assert result.downloaded == [wanted]
    assert len(list(root.glob("*" * 1))) >= 1
    assert set(Catalog.load(root).entries) == {wanted}


def test_no_verify_problems_after_a_clean_fetch(release, tmp_path):
    root = tmp_path / "cache"
    client.fetch("base", release["url"], root=root, keys=release["keys"], offline=False)
    manifest, problems = client.verify_cache(root, keys=release["keys"], deep=True)
    assert manifest is not None
    assert problems == []


# --- tamper ------------------------------------------------------------------


def test_a_tampered_blob_is_rejected_and_not_cached(release, tmp_path):
    """The mirror serves the right name and the wrong bytes."""
    victim = release["manifest"].blobs[0]
    served = release["out"] / "blobs" / victim.sha256
    original = served.read_bytes()
    served.write_bytes(original[:-1] + bytes([original[-1] ^ 0xFF]))

    root = tmp_path / "cache"
    with pytest.raises(client.BlobVerificationError, match="sha256 mismatch"):
        client.fetch(
            "base",
            release["url"],
            root=root,
            keys=release["keys"],
            offline=False,
            only=[victim.key],
        )

    assert not (root / victim.sha256).exists(), "tampered bytes entered the cache"
    assert not list((root / ".partial").glob("*.part")), (
        "a bad partial survived and could be resumed into a successful fetch"
    )


def test_a_tampered_manifest_does_not_verify(release, tmp_path):
    path = release["out"] / "manifest.json"
    payload = json.loads(path.read_text())
    payload["min_glaurung_version"] = "99.0.0"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    with pytest.raises(client.TrustError, match="does not verify"):
        client.fetch(
            "base",
            release["url"],
            root=tmp_path / "cache",
            keys=release["keys"],
            offline=False,
        )


def test_a_manifest_signed_by_an_untrusted_key_is_refused(release, tmp_path):
    _, stranger = minisign.generate_keypair()
    with pytest.raises(client.TrustError, match="not trusted"):
        client.fetch(
            "base",
            release["url"],
            root=tmp_path / "cache",
            keys=[stranger],
            offline=False,
        )


def test_verify_cache_catches_a_blob_edited_in_place(release, tmp_path):
    """Deep verification exists for exactly this: bit-rot a size check misses."""
    root = tmp_path / "cache"
    client.fetch("base", release["url"], root=root, keys=release["keys"], offline=False)
    victim = release["manifest"].blobs[0]
    cached = root / victim.sha256
    data = bytearray(cached.read_bytes())
    data[10] ^= 0xFF  # same length, different bytes
    cached.write_bytes(bytes(data))

    _, shallow = client.verify_cache(root, keys=release["keys"], deep=False)
    assert shallow == [], "a size-only check cannot see this, by construction"
    _, deep = client.verify_cache(root, keys=release["keys"], deep=True)
    assert any("sha256" in problem for problem in deep)


# --- downgrade ---------------------------------------------------------------


def test_a_lower_serial_is_refused_even_when_correctly_signed(tmp_path, serve):
    corpus = _write_corpus(tmp_path / "corpus")
    key_path = tmp_path / "keys" / "signing.key"
    root = tmp_path / "cache"

    new = tmp_path / "release-5"
    _publish(corpus, new, key_path, serial=5, set_version="2026.09.5")
    url_new = serve(new)
    manifest_new = _rewrite_urls(new, url_new, key_path)
    public = minisign.SecretKey.read(key_path).public_key()

    client.fetch(
        "base", f"{url_new}/manifest.json", root=root, keys=[public], offline=False
    )
    assert Catalog.load(root).serial == 5

    old = tmp_path / "release-4"
    _publish(corpus, old, key_path, serial=4, set_version="2026.09.4")
    url_old = serve(old)
    _rewrite_urls(old, url_old, key_path)

    with pytest.raises(client.DowngradeError, match="serial 4"):
        client.fetch(
            "base", f"{url_old}/manifest.json", root=root, keys=[public], offline=False
        )
    assert Catalog.load(root).serial == 5, "the cache was downgraded anyway"
    assert manifest_new.serial == 5


def test_the_same_serial_is_accepted(tmp_path, serve, release):
    """Re-fetching the current set must not be mistaken for a downgrade."""
    root = tmp_path / "cache"
    client.fetch("base", release["url"], root=root, keys=release["keys"], offline=False)
    again = client.fetch(
        "base", release["url"], root=root, keys=release["keys"], offline=False
    )
    assert again.manifest.serial == release["manifest"].serial


def test_a_manifest_for_another_set_is_refused(release, tmp_path):
    with pytest.raises(client.FetchError, match="asked for set"):
        client.fetch(
            "windows",
            release["url"],
            root=tmp_path / "cache",
            keys=release["keys"],
            offline=False,
        )


def test_a_set_needing_a_newer_glaurung_is_refused(release, tmp_path):
    with pytest.raises(client.FetchError, match="needs glaurung"):
        client.fetch(
            "base",
            release["url"],
            root=tmp_path / "cache",
            keys=release["keys"],
            offline=False,
            glaurung_version="0.0.1",
        )


def test_an_expired_set_warns_but_still_works(tmp_path, serve):
    corpus = _write_corpus(tmp_path / "corpus", count=1)
    out = tmp_path / "release"
    key_path = tmp_path / "keys" / "signing.key"
    _publish(corpus, out, key_path)

    stale = replace(
        Manifest.read(out / "manifest.json"), valid_until="2000-01-01T00:00:00Z"
    )
    stale.write(out / "manifest.json")
    base_url = serve(out)
    manifest = _rewrite_urls(out, base_url, key_path)
    assert manifest.is_expired()

    result = client.fetch(
        "base",
        f"{base_url}/manifest.json",
        root=tmp_path / "cache",
        keys=[minisign.SecretKey.read(key_path).public_key()],
        offline=False,
    )
    assert any("expired" in w for w in result.warnings)
    assert result.downloaded, "an expired set must still be usable, not refused"


# --- resume ------------------------------------------------------------------


def test_a_partial_download_resumes_over_http_range(release, tmp_path):
    """Half a blob on disk plus a `Range` request equals the whole blob."""
    blob = max(release["manifest"].blobs, key=lambda b: b.size_bytes)
    root = tmp_path / "cache"
    partial_dir = root / ".partial"
    partial_dir.mkdir(parents=True)
    full = (release["out"] / "blobs" / blob.sha256).read_bytes()
    half = len(full) // 2
    (partial_dir / f"{blob.sha256}.part").write_bytes(full[:half])
    release["log"].clear()

    result = client.fetch(
        "base",
        release["url"],
        root=root,
        keys=release["keys"],
        offline=False,
        only=[blob.key],
    )
    assert result.downloaded == [blob.key]
    assert (root / blob.sha256).read_bytes() == full

    # The assertion that makes this test about resume rather than about
    # re-download: the server answered 206 from the halfway offset, and fewer
    # than the blob's bytes crossed the wire.
    blob_requests = [row for row in release["log"] if blob.sha256 in row[0]]
    assert blob_requests == [(f"/blobs/{blob.sha256}", half, len(full) - half, 206)]


def test_a_corrupt_partial_is_discarded_rather_than_resumed(release, tmp_path):
    """Resuming onto wrong bytes would produce a hash failure forever."""
    blob = max(release["manifest"].blobs, key=lambda b: b.size_bytes)
    root = tmp_path / "cache"
    partial_dir = root / ".partial"
    partial_dir.mkdir(parents=True)
    (partial_dir / f"{blob.sha256}.part").write_bytes(b"\x00" * (blob.size_bytes // 2))

    with pytest.raises(client.BlobVerificationError):
        client.fetch(
            "base",
            release["url"],
            root=root,
            keys=release["keys"],
            offline=False,
            only=[blob.key],
        )
    assert not list(partial_dir.glob("*.part"))

    # ...and the next attempt, starting clean, succeeds.
    result = client.fetch(
        "base",
        release["url"],
        root=root,
        keys=release["keys"],
        offline=False,
        only=[blob.key],
    )
    assert result.downloaded == [blob.key]


# --- offline -----------------------------------------------------------------


def test_offline_uses_the_cache_and_never_the_network(release, tmp_path, monkeypatch):
    root = tmp_path / "cache"
    client.fetch("base", release["url"], root=root, keys=release["keys"], offline=False)

    def explode(*args, **kwargs):
        raise AssertionError("offline mode reached the network")

    monkeypatch.setattr(client.urllib.request, "urlopen", explode)
    result = client.fetch(
        "base", release["url"], root=root, keys=release["keys"], offline=True
    )
    assert len(result.already_cached) == len(release["manifest"].blobs)
    assert result.downloaded == []


def test_the_env_var_alone_forces_offline(release, tmp_path, monkeypatch):
    root = tmp_path / "cache"
    client.fetch("base", release["url"], root=root, keys=release["keys"], offline=False)
    monkeypatch.setenv(paths.ENV_OFFLINE, "1")

    def explode(*args, **kwargs):
        raise AssertionError("GLAURUNG_SIGS_OFFLINE=1 reached the network")

    monkeypatch.setattr(client.urllib.request, "urlopen", explode)
    result = client.fetch("base", release["url"], root=root, keys=release["keys"])
    assert result.downloaded == []


def test_an_explicit_online_call_overrides_the_env_var(release, tmp_path, monkeypatch):
    """A caller that means "go online" is not silently overridden."""
    monkeypatch.setenv(paths.ENV_OFFLINE, "1")
    result = client.fetch(
        "base",
        release["url"],
        root=tmp_path / "cache",
        keys=release["keys"],
        offline=False,
    )
    assert result.downloaded


def test_offline_falls_back_to_the_bundled_set_on_a_fresh_install(
    tmp_path, monkeypatch
):
    """The whole point of shipping `data/sigs/base/` in the wheel."""
    root = tmp_path / "empty-cache"

    def explode(*args, **kwargs):
        raise AssertionError("the bundled fallback reached the network")

    monkeypatch.setattr(client.urllib.request, "urlopen", explode)
    result = client.fetch("base", root=root, offline=True)

    assert result.source.startswith("bundled:")
    assert result.downloaded, "bundled blobs should be installed into the cache"
    for blob in result.manifest.blobs:
        assert (root / blob.sha256).is_file()
    assert Catalog.load(root).entries, (
        "an offline fetch must write catalog.json, or the Rust loader cannot "
        "map a library key to a blob digest"
    )


def test_offline_with_nothing_cached_and_no_bundled_set_raises(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.ENV_DATA_DIR, str(tmp_path / "no-such-data"))
    with pytest.raises(client.OfflineError):
        client.fetch("base", root=tmp_path / "cache", offline=True, keys=[])


# --- URL policy --------------------------------------------------------------


def test_only_http_https_and_file_urls_are_followed(tmp_path):
    for url in ("ftp://example.invalid/manifest.json", "gopher://x/y"):
        with pytest.raises(client.FetchError, match="refusing URL"):
            client.fetch("base", url, root=tmp_path / "cache", offline=False, keys=[])


def test_a_file_url_manifest_works(tmp_path, release):
    """`file://` is a real transport here, for air-gapped mirrors and tests."""
    url = (release["out"] / "manifest.json").as_uri()
    result = client.fetch(
        "base",
        url,
        root=tmp_path / "cache-file",
        keys=release["keys"],
        offline=False,
        only=[],
    )
    assert result.manifest.serial == release["manifest"].serial
