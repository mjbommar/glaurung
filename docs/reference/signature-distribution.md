# Signature-set distribution

> **Kind:** reference · **Status:** maintained

How a signature library gets from a harvester onto a user's machine: a signed,
content-addressed manifest, a publish tool, a verifying client, and a cache the
Rust loader reads. For what a signature *is* and how one is built from a `.a`
archive, see
[FLIRT-style signature libraries](function-signature-libraries.md).

**Nothing has been published yet.** The channel is implemented and exercised
end to end against a locally published release; creating the real GitHub
release is a maintainer action, and `tools/publish_signature_set.py` stops at
printing the commands.

## Why a channel at all

Measured on 2026-09-03: a glibc library built from this machine's own `libc.a`
names 731 of 1,090 text functions in a stripped `gcc -O2 -static` binary, 0
wrong. The **same binary** against glibc libraries from Debian trixie, bookworm
and bullseye scores 1, 0 and 0. Cross-distro transfer is nil; adjacent releases
inside one distro line share 26 to 43 percent of their signatures.

So the unit of usefulness is one library per `(library, version, variant,
arch)`, the corpus is 10^5 to 10^6 signatures rather than 10^3, and it cannot
live in a wheel — PyPI's limits are 100 MB per file and 10 GB per project, and
the corpus is not the thing that should be spending them. **PyPI carries the
resolver and a fallback; the corpus goes through a release channel.**

## The channel

| Tier | Where | Why |
|---|---|---|
| Primary | GitHub Releases on a dedicated `glaurung-sigs` repository | 2 GiB per asset, 1000 assets per release, no bandwidth cap in the release docs. Immutable Releases carry Sigstore attestations automatically. |
| Mirror | Cloudflare R2 | Contractual `$0` egress. Must exist *before* GitHub's acceptable-use throttling makes it necessary, not after. |
| Optional mirror | Hugging Face datasets | Chunk-level dedup suits the measured 26-43 percent cross-release overlap, but the anonymous resolver limit is 3,000 requests per 5-minute window per IP, which a many-file sync hits. Good mirror, wrong primary. |
| Never | the git repository itself | 100 MiB per file hard block, 5 GB soft repository ceiling. |

Blobs are **named by their sha256**, on disk and in every URL. Three
consequences, and they are the whole design:

* mirrors are interchangeable — the client tries each URL in turn and accepts
  whichever answers with bytes that hash correctly;
* a stale mirror cannot serve a mismatched file under a live name;
* the cross-release overlap deduplicates for free at the blob level.

## The manifest

One JSON document per set, and the **only** signed object. Every blob's sha256
is inside it, so one Ed25519 signature transitively covers the set — the model
Nix uses for `narinfo`, and the reason a blob needs no signature of its own.

The schema is `data/sigs/manifest.schema.json`, and it is *executed* rather
than decorative: `glaurung.sigs.manifest.validate_against_schema` implements
the subset of JSON Schema it uses, with no third-party dependency, and both the
publish tool and the tests run it. A schema nothing checks is a second source
of truth that silently drifts.

```jsonc
{
  "schema_version": 1,
  "set": "base",
  "set_version": "2026.09.1",
  "serial": 1,                              // monotonic; downgrade defence
  "built_utc": "2026-09-03T13:00:00Z",
  "valid_until": "2027-03-02T13:00:00Z",
  "min_glaurung_version": "0.1.0",
  "blobs": [
    {
      "key": "libz/1:1.2.11.dfsg-2ubuntu9.2/ubuntu-22.04-gcc-11.4.0/x86_64",
      "kind": "flirt-masked-pattern-v1",    // identity scheme of the records
      "format": "flirt-json/2",             // container; `gsig/1` later
      "compression": "none",
      "sha256": "62f1104af476c3fe…",        // the blob's name, everywhere
      "size_bytes": 69783,
      "uncompressed_bytes": 69783,
      "signatures": 109,
      "licence": "signatures and names only, derived; inputs under their own licence",
      "provenance": {
        "source": "docker-harvest",
        "package": "zlib1g-dev",
        "version": "1:1.2.11.dfsg-2ubuntu9.2",
        "arch": "x86_64",
        "archive": "libz.a",
        "input_sha256": "478ed7d354847b3d…",
        "variant": "ubuntu-22.04-gcc-11.4.0",
        "triplet": "x86_64-linux-gnu"
      },
      "urls": [
        "https://github.com/glaurung-re/glaurung-sigs/releases/download/2026.09.1/62f1104af476c3fe…",
        "https://sigs.glaurung.dev/blob/62f1104af476c3fe…",
        "hf://datasets/glaurung/sigs/blobs/62f1104af476c3fe…"
      ]
    }
  ]
}
```

Three fields exist purely as defences, and the client checks all three:

**`serial`** is monotonic. The client refuses a manifest whose serial is below
the one it already has cached, so an attacker cannot replay a genuinely-signed
older set to reintroduce a withdrawn blob. Equality is accepted — re-fetching
the current set is not a downgrade.

**`valid_until`** is a staleness horizon, not an expiry. Past it the client
still works and says the set is stale; refusing would brick an air-gapped
install, which is a worse outcome than an old signature library.

**`min_glaurung_version`** is the producer saying an older reader cannot
correctly interpret this set. It is how a future `gsig/1` set will say "you
need a reader that understands chunked containers" instead of letting every old
client mis-parse it.

Serialisation is deterministic — sorted keys, sorted blobs, fixed indent, one
trailing newline — because a document that re-serialises differently breaks its
own signature for no reason and makes "did this release change?" unanswerable
by diff.

## Signing

**minisign, as the mandatory floor.** The artefacts are tiny, the file formats
are two base64 lines, and the *trusted comment* field exists for exactly the
problem this channel has.

The trusted comment carries the set name, version, serial, blob count and build
time:

```
trusted comment: glaurung-sigs set=base version=2026.09.1 serial=1 blobs=171 built=2026-09-03T13:00:00Z
```

A `.minisig` holds **two** signatures: one over the file (BLAKE2b-512 prehashed,
minisign's default since 0.10) and a *global* one over
`signature || trusted_comment`. The client checks both, and then checks that the
signed trusted comment describes the manifest body it just parsed. Without that
last step the serial would be signed in one place and unsigned in another;
with it, an attacker who relabels a genuinely-signed older manifest invalidates
the global signature.

Verification is `glaurung.sigs.minisign`, which prefers `cryptography` when it
is importable and otherwise uses `glaurung.sigs.ed25519`, a dependency-free
RFC 8032 implementation checked against the RFC's own test vectors and
cross-checked byte for byte against `cryptography`. `cryptography` is in
`uv.lock` at 49.0.0 but only *transitively*, via `authlib`; nothing guarantees
it is importable in an installed wheel, and a verifier that is sometimes absent
is not a verifier.

Anyone can check a release with stock tools:

```bash
minisign -Vm manifest.json -p data/sigs/trusted-keys/glaurung-sigs.pub
sha256sum -c SHA256SUMS
```

### Key rotation

Trusted keys are a *directory* (`data/sigs/trusted-keys/*.pub`), not one
embedded key, so rotation is a non-event: the new key ships beside the old one
for a release or two, both verify, then the old one is deleted. A single key
compiled into the binary makes rotation a flag day where every unupgraded
client breaks the moment the key changes.

The key that ships today is a **development** key. See
[`data/sigs/trusted-keys/README.md`](../../data/sigs/trusted-keys/README.md)
for what the maintainer must do before the first real release.

### Sigstore

Documented, not implemented. GitHub Immutable Releases attach Sigstore bundle
attestations automatically, and `cosign sign-blob` can add a transparency-log
bundle beside the manifest. Both are welcome as an **optional layer** for
anyone who wants Rekor provenance. Neither becomes a client dependency: the
`sigstore` Rust crate self-describes as experimental at 0.14.0, and a verifier
that needs OIDC and a network round trip cannot work air-gapped, which is
precisely when an offline signature library matters most.

## Where verification lives, and why not in Rust

**Verification is Python, at fetch time. The Rust loader trusts the cache.**

That is a decision, not an omission. `minisign-verify` 0.2.5 (MIT, zero
dependencies) would make in-process verification about thirty lines, and it was
considered. Three reasons it is not there:

1. **It would verify nothing new.** A blob's file name *is* its sha256, and it
   is written into the cache only after its bytes hash to that name. An
   attacker who can write to `~/.cache/glaurung/sigs/` to plant a blob can
   equally overwrite the `.so` the loader is running from; re-checking the
   manifest in-process does not close that gap, it only moves it.
2. **It would make key rotation a release.** An embedded public key ships in
   the binary. A key directory read at fetch time can gain a key without
   recompiling anything.
3. **The Rust loader has no network and no manifest.** It resolves a library
   key to a file through `catalog.json` and mmaps it. Adding signature parsing
   there means adding manifest parsing, key management, and an error path for
   "cached but unverifiable" to a code path whose whole job is to be fast and
   silent.

What *would* change this: a threat model in which the cache is shared between
users or delivered by a third party — a system-wide `/usr/share` install, or a
distro packaging the corpus. At that point the loader stops being the only
writer's reader, and in-process verification earns its cost. The catalog
already records `verified_utc`, `verified_by_key_id` and `manifest_sha256`, so
the hook exists.

## The client

`glaurung.sigs.client.fetch(set_name, manifest_url, …)`, in order:

1. Download the manifest and its `.minisig`. **Nothing is trusted yet.**
2. Verify both signatures against a bundled trusted key, and cross-check the
   trusted comment against the manifest body.
3. Refuse a serial below the cached one; refuse a manifest for another set;
   refuse a set needing a newer Glaurung; warn if past `valid_until`.
4. For each missing blob, try each URL in order. Resume a partial download with
   an HTTP `Range` request. Hash what arrived. A mismatch **deletes the partial
   file** — a bad partial must never be resumed into a successful fetch — and
   moves to the next mirror.
5. Write `manifest.json`, `manifest.json.minisig` and `catalog.json`.

Only `http`, `https` and `file` URLs are followed; anything else is refused
before a request is made. `file://` is a real transport, for air-gapped mirrors
and for the end-to-end tests, which exercise the same code as a network fetch
rather than a special case.

### Resolution order

| Order | Location | Set by |
|---|---|---|
| 1 | `$GLAURUNG_SIG_DIR` | the user; shared with the Rust loader |
| 2 | `~/.cache/glaurung/sigs/` | default |
| 3 | the bundled `base` set in the wheel | the distribution |

The cache holds blobs named by sha256 plus `catalog.json`, which maps a library
key to the digest that answers it. That file is the Rust loader's entry point.

### Environment variables

| Variable | Effect |
|---|---|
| `GLAURUNG_SIG_DIR` | Cache root override. The same variable `src/flirt/` consults first. |
| `GLAURUNG_SIGS_OFFLINE` | `1`/`true`/`yes`/`on` forbids every network call. Mirrors `HF_HUB_OFFLINE`. |
| `GLAURUNG_SIGS_MANIFEST_URL` | Where the signed manifest is fetched from; a mirror, or a `file://` URL. |
| `GLAURUNG_SIGS_TRUSTED_KEYS` | Directory of trusted `*.pub` keys, replacing the bundled set. |
| `GLAURUNG_SIGS_DATA_DIR` | The bundled read-only data directory. Exists so a test can point at an unpacked wheel. |

All five are in [environment variables](environment-variables.md).

### Offline mode

`GLAURUNG_SIGS_OFFLINE=1` (or `glaurung sigs fetch --offline`) forbids the
network and falls back to the cache, then to the bundled set. The bundled
blobs are copied into the cache and `catalog.json` is written, so the Rust
loader can resolve them — a cache the loader cannot read is not a cache.

### The bundled fallback

Two blobs, 125 signatures, 76,414 bytes: the `mathlib` demo library built from
this repository's own sample archive, and `libz` 1.2.11 from Ubuntu 22.04
(109 signatures). It ships in the wheel via `[tool.maturin].include`, and
`python/tests/test_sigs_packaging.py` caps the whole of `data/sigs/` at
256 KiB. It is a fallback, not the corpus.

One packaging wart, measured with `uv run maturin build` on 2026-09-03: maturin
preserves a path relative to the project root for any included file that is not
under `python-source`, so `data/sigs/*` lands at the **wheel root** and installs
to `<site-packages>/data/sigs/`. `glaurung.sigs.paths` resolves both that and
the source-tree layout from `__file__`, never from the cwd — which is the
defect `src/flirt/mod.rs`'s `default_library_path` still has, and the reason
the shipped library used to be findable only from a source checkout. Moving the
data under `python/glaurung/data/` would put it inside the package instead; it
is a one-line change to `include` plus one candidate in `paths.py`.

## The CLI

```bash
glaurung sigs status                       # cache, set, serial, trusted keys
glaurung sigs list [--cached-only] [--arch x86_64]
glaurung sigs fetch [--set base] [--manifest-url URL] [--offline] [--key KEY]
glaurung sigs verify [--shallow]           # re-check the signature and every digest
glaurung sigs path [LIBRARY_KEY]           # roots, or one blob's file
```

Every verb but `fetch` is offline by construction. All of them take `--json`.
`verify` without `--shallow` re-hashes every cached blob, which is what catches
bit-rot and hand edits that a size check cannot see.

## Publishing a release, step by step

The maintainer does this. `tools/publish_signature_set.py` imports no network
client at all — `python/tests/test_sigs_publish.py` asserts that structurally —
so it cannot publish, only prepare.

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"

# 1. Build the release directory from a harvest.
uv run python tools/publish_signature_set.py \
    --blobs "$HOME/.cache/glaurung/system-libs/sigs" \
    --set base --set-version 2026.09.1 --serial 1 \
    --secret-key "$HOME/.cache/glaurung/keys/glaurung-sigs.key" \
    --out "$HOME/.cache/glaurung/release/2026.09.1"
```

It writes `blobs/<sha256>` (one file per blob, deduplicated by digest),
`manifest.json`, `manifest.json.minisig`, `SHA256SUMS` and `NOTICE`; validates
the manifest against the shipped schema; verifies its own signature with the
public half before saying anything succeeded; and prints the `gh release` and
mirror commands **without running them**.

Two refusals worth knowing:

* **Empty libraries are dropped** (`--min-signatures`, default 1). Five glibc
  archives have been 8-byte stubs since 2.34 and MinGW import libraries are
  pure 6-byte thunks, so a harvest legitimately yields signature-less outputs.
  Publishing them inflates the set with entries that can never match anything.
* **A key collision is a hard error.** Two blobs claiming one
  `(library, version, variant, arch)` key with different bytes means the
  harvester is not distinguishing two builds. `--prefer-image` is the
  operator's escape; see the note below.

```bash
# 2. Check it the way a stranger would.
cd "$HOME/.cache/glaurung/release/2026.09.1"
minisign -Vm manifest.json -p <the production public key>
sha256sum -c SHA256SUMS

# 3. Create the release. Immutable Releases need draft, upload, publish:
#    an asset uploaded after publication returns 422.
gh release create 2026.09.1 --repo glaurung-re/glaurung-sigs --draft \
    --title 'glaurung signature set base 2026.09.1' --notes-file NOTICE
gh release upload 2026.09.1 --repo glaurung-re/glaurung-sigs \
    manifest.json manifest.json.minisig SHA256SUMS NOTICE
gh release upload 2026.09.1 --repo glaurung-re/glaurung-sigs blobs/*
gh release edit 2026.09.1 --repo glaurung-re/glaurung-sigs --draft=false

# 4. Mirror to R2, then optionally Hugging Face.
rclone copy blobs r2:glaurung-sigs/blob --checksum --transfers 8
rclone copy manifest.json         r2:glaurung-sigs/v1/
rclone copy manifest.json.minisig r2:glaurung-sigs/v1/

# 5. Verify from the outside, as a user.
GLAURUNG_SIG_DIR="$TMPDIR/verify-cache" uv run glaurung sigs fetch \
    --manifest-url https://github.com/glaurung-re/glaurung-sigs/releases/download/2026.09.1/manifest.json
GLAURUNG_SIG_DIR="$TMPDIR/verify-cache" uv run glaurung sigs verify
```

The serial must **exceed** every previously published serial for the set. That
is what makes the downgrade defence work; a re-issue at the same serial with
different content defeats it.

## Legal position

We redistribute **signatures and names, never archives or objects**. FLIRT's
own author states the property the format is designed for: a signature file
"contains no byte from the original libraries, except for the names of the
functions". Every blob carries provenance sufficient to re-fetch the input from
its original distributor and re-derive the blob independently, which is what
makes the claim checkable rather than asserted.

`NOTICE` in every release directory states this, lists per-blob provenance, and
records the takedown position: if a rights-holder objects, the affected blobs
are withdrawn in a new manifest with a higher serial — and because clients
refuse a lower serial, a withdrawal cannot be rolled back by replaying an older
signed manifest.

Libraries whose licence forbids redistribution of the inputs, or whose licence
cannot be determined, are not consumed at all. Sets derived on a licensed build
device (MSVC) are marked as such in their provenance.

## A defect this found in the harvester

Running the publish tool over the 2026-09-03 Docker harvest, **134 of 245
library keys were contested** (in the 419-library snapshot; the corpus grew to
561 while this was being written): two or three blobs claiming one
`(library, version, variant, arch)`. Diffing a colliding pair shows they differ
in exactly one line —

```
< "archive": "/home/…/system-libs/linux-amd64/arm-linux-gnueabihf/lib/libBrokenLocale.a"
> "archive": "/home/…/system-libs/linux-arm64/arm-linux-gnueabihf/lib/libBrokenLocale.a"
```

— an absolute path from the machine that ran the build, embedded in the blob's
own provenance. The builder image is not part of a signature's identity: the
same cross-compiled `arm-linux-gnueabihf` glibc is the same library whichever
host built it. So those blobs *should* hash identically and deduplicate for
free, and instead they collide.

That is a harvester defect, not a distribution one. The publish tool fails hard
on it by default, which is what keeps it visible; `--prefer-image linux-amd64
--prefer-image linux-arm64 --prefer-image windows-amd64` is the operator's
escape and is what the dry run used. Once the absolute path is out of the
emitted blob, the collisions become dedups.

## The dry run, measured

```bash
uv run python tools/publish_signature_set.py \
    --blobs "$HOME/.cache/glaurung/system-libs/sigs" \
    --set base --set-version 2026.09.1 --serial 1 \
    --prefer-image linux-amd64 --prefer-image linux-arm64 \
    --prefer-image windows-amd64 \
    --secret-key "$HOME/.cache/glaurung/keys/glaurung-sigs-dev.key" \
    --out "$HOME/.cache/glaurung/release/2026.09.1"
```

Against the harvest as of 2026-09-03 09:17 (561 libraries; the harvester lane
was still growing it):

| | |
|---|---|
| source files | 561 |
| skipped (0 signatures, or superseded by `--prefer-image`) | 269 |
| blobs published | 292 |
| signatures | 167,938 |
| blob bytes | 220,437,620 (212 MiB on disk) |
| `manifest.json` | 383,659 bytes |
| `manifest.json.minisig` | 351 bytes |
| `SHA256SUMS` | 40,084 bytes; `sha256sum -c` reports 293 OK |
| `NOTICE` | 40,224 bytes |

Then served over `http://127.0.0.1` and driven through the client:

| Step | Result |
|---|---|
| fetch all 292 blobs | 292 downloaded, 220,437,620 bytes, no warnings, signed by `FA6FDB763B3E76EF` |
| `verify_cache(deep=True)` | serial 1, no problems |
| re-fetch | 0 downloaded, 292 already cached |
| offline with `urlopen` poisoned | 292 from cache, no network call |
| replay a lower serial, correctly signed | `DowngradeError` |
| flip one byte of one served blob | `BlobVerificationError`, nothing cached, no partial left |
| valid signature from an untrusted key | `TrustError` |

At 220 MB uncompressed this set would be a legitimate GitHub release (2 GiB per
asset, 292 of 1000 assets) but is not the `base` set the design calls for:
`base` is glibc, libm, libstdc++ and libz for current and previous Debian,
Ubuntu, Alpine and Fedora on amd64 and arm64, about 50 keys. Scoping the
harvest is the harvester lane's call, not this one's.

## Not done yet

* **Transport compression is `none`.** The field is in the manifest and the
  client honours it, but blobs are stored uncompressed so the Rust loader can
  read a cache file directly. `gsig/1` compresses internally with 64 KiB zstd
  chunks, which makes transport compression redundant; revisit only if the
  corpus ships as something other than `gsig`.
* **No delta channel.** ClamAV's `cdiff` model — ship only what changed — is
  worth having once full re-downloads become the complaint. Content-addressing
  already means an unchanged blob is never re-fetched, which covers most of it.
* **No R2 bucket exists.** The manifest lists the URL and the client will try
  it; it must be created before GitHub throttling makes it necessary.
* **Sigstore attestations are not attached.** They come free with GitHub
  Immutable Releases once the repository exists.
