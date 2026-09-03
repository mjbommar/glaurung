# Signature-set distribution

> **Kind:** reference · **Status:** maintained

How a signature library gets from a harvester onto a user's machine: a signed,
content-addressed manifest, a publish tool, a verifying client, and a cache the
Rust loader reads. For what a signature *is* and how one is built from a `.a`
archive, see
[FLIRT-style signature libraries](function-signature-libraries.md).

**Nothing has been published yet.** The channel is implemented and exercised
end to end against a locally published release, and the `assets.glaurung.dev`
infrastructure described below now exists. Uploading the first real manifest,
and creating the first real GitHub release, both remain a maintainer action:
`tools/publish_signature_set.py` prints the S3 and GitHub commands by default
and only executes the S3 half when run with `--upload`; it never runs `gh`
itself.

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
| Primary | `assets.glaurung.dev` — an S3 bucket behind CloudFront, origin access control, in the maintainer's personal AWS account | No third-party release-asset limits, and the maintainer controls both the storage and the CDN outright. Chosen as primary because the maintainer has AWS and no other cloud account. |
| Secondary | GitHub Releases on a dedicated `glaurung-sigs` repository | 2 GiB per asset, 1000 assets per release, no bandwidth cap in the release docs. Immutable Releases carry Sigstore attestations automatically. Kept for redundancy if the CDN or the bucket has an incident. |
| Never | the git repository itself | 100 MiB per file hard block, 5 GB soft repository ceiling. |

Cloudflare R2 and Hugging Face datasets were both considered as mirrors and
dropped on 2026-09-03: the maintainer has AWS only, and running a second
provider's account for a mirror nobody has asked for yet is not worth the
operational surface. `docs/design/signature-library-program-2026-09-03.md`
Decision 4 records the amendment.

Blobs are **named by their sha256**, on disk and in every URL. Three
consequences, and they are the whole design:

* mirrors are interchangeable — the client tries each URL in turn and accepts
  whichever answers with bytes that hash correctly;
* a stale mirror cannot serve a mismatched file under a live name;
* the cross-release overlap deduplicates for free at the blob level.

### `assets.glaurung.dev`, in detail

| Resource | Value |
|---|---|
| S3 bucket | `assets.glaurung.dev`, `us-east-1`, private, versioned, SSE-S3 |
| Bucket policy | grants `GetObject` only to CloudFront distribution `E3A8M3Y3GUZ4ZD` via origin access control `E7HX29S4M25DX` — the bucket has no public access of its own |
| CloudFront distribution | `E3A8M3Y3GUZ4ZD` (`d14q5hxxut187.cloudfront.net`) |
| ACM certificate | `e464d88b-db18-4fa3-937b-03a72520b71c`, validated in Route 53 zone `Z01833141XUJONTNN0T91` |
| DNS | A/AAAA alias records for `assets.glaurung.dev` in that zone, pointed at the CloudFront distribution |
| `aws` CLI profile | `personal-sso` |

Object layout:

| Path | Contents | Cache-Control |
|---|---|---|
| `sigs/v1/manifest.json` | the signed manifest | `public, max-age=300` (short — this is the pointer clients re-check) |
| `sigs/v1/manifest.json.minisig` | its detached minisign signature | `public, max-age=300` |
| `sigs/blob/<sha256>.gsig.zst` | one blob, named by its digest | `public, max-age=31536000, immutable` (one year) |

**Invariants**, enforced by the publish tool and by convention:

* the bucket is **never** made public — every read goes through CloudFront,
  which is the only principal the bucket policy grants `GetObject` to;
* CloudFront is **never** bypassed for a real client (the bucket has no
  website endpoint and no public policy to bypass it *to*);
* a blob key is **never** overwritten or deleted once uploaded — content
  addressing means an existing key already holds the right bytes, and
  `tools/publish_signature_set.py --upload` checks with `aws s3api
  head-object` before every blob upload and skips it if the key exists;
* the manifest is uploaded **last**, after every blob it names — see
  "Publishing a release" below;
* a real manifest for this bucket is signed with the production key
  (`25655013D3F68BC1`, `data/sigs/trusted-keys/glaurung-sigs.pub`), never the
  development key (`FA6FDB763B3E76EF`) that today's `bundled-manifest.json`
  still carries. See
  [`data/sigs/trusted-keys/README.md`](../../data/sigs/trusted-keys/README.md).

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
        "https://assets.glaurung.dev/sigs/blob/62f1104af476c3fe….gsig.zst",
        "https://github.com/glaurung-re/glaurung-sigs/releases/download/2026.09.1/62f1104af476c3fe…"
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

Two keys ship today, deliberately: the production key
(`25655013D3F68BC1`), password-protected on the maintainer's own machine, and
a development key (`FA6FDB763B3E76EF`) kept trusted only because the bundled
fallback manifest is still signed with it. See
[`data/sigs/trusted-keys/README.md`](../../data/sigs/trusted-keys/README.md)
for the interactive signing command and what retires the development key.

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

The maintainer does this. `tools/publish_signature_set.py` builds the release
directory, always prints the GitHub Releases (secondary) commands without
running them, and drives the S3 (primary) upload itself — but only when told
to: by default it prints the exact `aws` commands instead of running them, and
`--upload` is what makes it real.

**Signing is external, and that is the normal flow, not a fallback.** The
production key (`data/sigs/trusted-keys/glaurung-sigs.pub`, key id
`25655013D3F68BC1`) is password-protected, on the maintainer's own machine,
and `glaurung.sigs.minisign.SecretKey` only reads minisign's password-less
form — correctly, since decrypting a scrypt-protected key needs a passphrase
no automated tool should ever see. So the tool never signs a real release
itself: it writes `manifest.json`, prints the exact `minisign -Sm ...`
command, and only *verifies* whatever `.minisig` comes back via `--signature`
before it will proceed. `--secret-key`/`--generate-key` (a throwaway
password-less key the tool signs with itself) are the **local-testing flow
only** — every worked example and fixture below that uses them is testing the
channel, not publishing to it.

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
OUT="$HOME/.cache/glaurung/release/2026.09.1"

# 1. Build the release directory from a harvest, naming the signature that
#    does not exist yet. This refuses (non-zero exit) and prints the exact
#    command to run by hand -- that refusal is the point of this first run.
uv run python tools/publish_signature_set.py \
    --blobs "$HOME/.cache/glaurung/system-libs/sigs" \
    --set base --set-version 2026.09.1 --serial 1 \
    --secret-key "$HOME/.cache/glaurung/keys/glaurung-sigs.key" \
    --out "$OUT" --signature "$OUT/manifest.json.minisig"

# 2. Run the printed command by hand. minisign prompts for the passphrase on
#    its controlling terminal; nothing here ever sees it.
minisign -Sm "$OUT/manifest.json" -s "$HOME/.cache/glaurung/keys/glaurung-sigs.key" \
    -t "2026.09.1 serial=1"

# 3. Re-run step 1's exact command. manifest.json is unchanged (same bytes
#    the signature above covers) and --signature now exists and verifies
#    against data/sigs/trusted-keys/*.pub, so the tool proceeds.
uv run python tools/publish_signature_set.py \
    --blobs "$HOME/.cache/glaurung/system-libs/sigs" \
    --set base --set-version 2026.09.1 --serial 1 \
    --secret-key "$HOME/.cache/glaurung/keys/glaurung-sigs.key" \
    --out "$OUT" --signature "$OUT/manifest.json.minisig"
```

It writes `blobs/<sha256>` (one file per blob, deduplicated by digest),
`manifest.json`, `SHA256SUMS` and `NOTICE`; validates the manifest against the
shipped schema; and, once `--signature` verifies, prints the S3 dry-run
commands and the GitHub commands, **neither run yet**. A rebuild whose blobs,
set name, version or serial differ from what `--signature` was made against
is refused outright (only `built_utc`/`valid_until` may legitimately differ
between the two runs above).

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
```

**3. Upload to S3 (`assets.glaurung.dev`, primary).** Blobs first, then the
signature, then the manifest last — a client must never see a manifest naming
a blob that is not there yet. Every blob key is checked with `head-object`
first and is skipped, never overwritten, if it already exists (a blob is
content-addressed and immutable, so an existing key already holds the right
bytes):

```bash
# One `head-object`/`cp` pair per blob (elided here; see the tool's own
# --upload dry-run output for the exact per-blob commands):
aws s3api head-object --bucket assets.glaurung.dev \
    --key sigs/blob/<sha256>.gsig.zst --profile personal-sso \
    || aws s3 cp blobs/<sha256> s3://assets.glaurung.dev/sigs/blob/<sha256>.gsig.zst \
        --profile personal-sso \
        --cache-control "public, max-age=31536000, immutable" \
        --content-type application/octet-stream

# Then the signature, then the manifest -- in that order.
aws s3 cp manifest.json.minisig s3://assets.glaurung.dev/sigs/v1/manifest.json.minisig \
    --profile personal-sso --cache-control "public, max-age=300" --metadata-directive REPLACE
aws s3 cp manifest.json s3://assets.glaurung.dev/sigs/v1/manifest.json \
    --profile personal-sso --cache-control "public, max-age=300" --metadata-directive REPLACE
```

`tools/publish_signature_set.py --upload --s3-bucket assets.glaurung.dev
--aws-profile personal-sso` runs exactly this (the `head-object` precheck
included) instead of requiring it by hand; drop `--upload` to see the same
commands printed rather than executed. `--metadata-directive REPLACE` is
S3-copy vocabulary — it does not change what a local-file upload does, since
that is always a fresh `PutObject`, but it is passed on the manifest and
signature commands so the intent ("these headers always win here") is
explicit at the call site rather than only in prose. GitHub Releases stays
print-only regardless of `--upload`:

```bash
# 4. Create the (secondary) GitHub release. Immutable Releases need
#    draft, upload, publish: an asset uploaded after publication returns 422.
gh release create 2026.09.1 --repo glaurung-re/glaurung-sigs --draft \
    --title 'glaurung signature set base 2026.09.1' --notes-file NOTICE
gh release upload 2026.09.1 --repo glaurung-re/glaurung-sigs \
    manifest.json manifest.json.minisig SHA256SUMS NOTICE
gh release upload 2026.09.1 --repo glaurung-re/glaurung-sigs blobs/*
gh release edit 2026.09.1 --repo glaurung-re/glaurung-sigs --draft=false

# 5. Verify from the outside, as a user.
GLAURUNG_SIG_DIR="$TMPDIR/verify-cache" uv run glaurung sigs fetch \
    --manifest-url https://assets.glaurung.dev/sigs/v1/manifest.json
GLAURUNG_SIG_DIR="$TMPDIR/verify-cache" uv run glaurung sigs verify
```

The serial must **exceed** every previously published serial for the set. That
is what makes the downgrade defence work; a re-issue at the same serial with
different content defeats it.

The production key (`25655013D3F68BC1`) exists and is trusted (installed at
`data/sigs/trusted-keys/glaurung-sigs.pub`); the bundled fallback manifest
shipped in the wheel today is still signed with the development key
(`FA6FDB763B3E76EF`, also still trusted, for that reason alone) and must be
re-signed with the production key before the development key can be retired
— see [`data/sigs/trusted-keys/README.md`](../../data/sigs/trusted-keys/README.md).

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
* **No manifest has actually been uploaded to `assets.glaurung.dev` yet.** The
  bucket, CloudFront distribution and DNS exist; the first real `--upload` run,
  with a production signing key, is a maintainer action still to happen.
* **Sigstore attestations are not attached.** They come free with GitHub
  Immutable Releases once the repository exists.
