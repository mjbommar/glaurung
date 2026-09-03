# Trusted minisign public keys

> **Kind:** reference · **Status:** maintained

Every `*.pub` in this directory is a key whose signature over a signature-set
manifest this installation will accept. `glaurung.sigs.client.load_trusted_keys`
reads the whole directory, and `glaurung sigs status` prints the key ids.

## `glaurung-sigs-dev.pub` — a DEVELOPMENT key, replace before any real release

Key id `FA6FDB763B3E76EF`, generated on 2026-09-03 by
`tools/publish_signature_set.py --generate-key` to make the distribution
channel testable end to end without waiting on a maintainer key ceremony.

**Its secret half lives outside this repository, on one development machine,
and has signed nothing that was ever published.** It exists so the bundled
fallback manifest in `data/sigs/bundled-manifest.json` carries a real
signature rather than a placeholder, and so the fetch path can be exercised
against a locally published release.

Before the first real release the maintainer must:

1. Generate a production keypair on a machine they control, with stock
   minisign: `minisign -G -s glaurung-sigs.key -p glaurung-sigs.pub`. (Our
   `--generate-key` writes minisign's password-less form; a production key
   should be password-protected, which only the minisign binary can do
   interactively.)
2. Commit **only** the `.pub` here, with a note recording its id and the date.
3. Re-sign `data/sigs/bundled-manifest.json` with the production key — see the
   "Rebuilding the bundled set" section of `data/sigs/README.md`.
4. Delete `glaurung-sigs-dev.pub`, which is what retires the development key.

## Why a directory and not one embedded key

Key rotation has to be a non-event. A new key ships beside the old one for a
release or two, both verify, then the old one is deleted — so a client that
has not upgraded yet still verifies, and a client that has upgraded already
accepts the new key. A single key compiled into the binary makes rotation a
flag day, where every unupgraded client breaks the moment the key changes.

## What a key here can and cannot do

It can attest that a manifest — the set name, version, monotonic serial, and
every blob's sha256 — came from whoever holds the corresponding secret. It
cannot attest anything about the *contents* of a blob beyond its digest, and
it is not a statement about the licence or provenance of the inputs; those are
per-blob fields in the manifest and are covered by the same signature only in
the sense that they cannot be edited without breaking it.

## Never commit a secret key

A `.key` file under `data/sigs/` is a leaked signing key, not a test fixture.
`python/tests/test_sigs_minisign.py::test_no_secret_key_was_ever_committed`
fails if one appears.
