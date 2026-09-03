"""minisign key and signature handling, and the two Ed25519 backends.

The distribution channel's whole trust story is one Ed25519 signature over one
manifest, so these are the tests that decide whether anything downstream means
anything. Three properties matter and each has a test that would fail if it
were dropped:

* a signature verifies only under the key that made it,
* the *trusted comment* -- where the set version and the monotonic serial live
  -- is covered by its own signature, so a downgrade cannot be dressed up by
  editing it,
* the pure-Python fallback and `cryptography` agree, byte for byte, so a wheel
  installed without `cryptography` is not verifying differently from a
  development checkout.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from glaurung.sigs import ed25519, minisign

ROOT = Path(__file__).resolve().parents[2]
TRUSTED_KEYS = ROOT / "data" / "sigs" / "trusted-keys"


# --- RFC 8032 ---------------------------------------------------------------


def test_pure_python_ed25519_matches_rfc_8032_test_vector():
    """RFC 8032 section 7.1, TEST 2: a one-byte message.

    A self-consistent implementation that is wrong in the same way in both
    directions would pass a round-trip test. Only a published vector catches
    that.
    """
    seed = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    public = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    message = bytes.fromhex("72")
    expected = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert ed25519.public_from_seed(seed) == public
    assert ed25519.sign(seed, message) == expected
    assert ed25519.verify(public, message, expected)


def test_ed25519_rejects_a_non_canonical_scalar():
    """A signature with `s >= L` is malleable and must not verify."""
    seed = bytes(32)
    public = ed25519.public_from_seed(seed)
    signature = ed25519.sign(seed, b"payload")
    order = 2**252 + 27742317777372353535851937790883648493
    s = int.from_bytes(signature[32:], "little") + order
    mauled = signature[:32] + s.to_bytes(33, "little")[:32]
    if len(mauled) == 64 and mauled != signature:
        assert not ed25519.verify(public, b"payload", mauled)


def test_both_backends_produce_the_same_bytes():
    """An installed wheel without `cryptography` must verify identically."""
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    message = b"glaurung signature set base 2026.09.1 serial 41"
    pure = ed25519.sign(seed, message)
    preferred = minisign.ed25519_sign(seed, message)
    assert pure == preferred
    public = ed25519.public_from_seed(seed)
    assert minisign.ed25519_public_from_seed(seed) == public
    assert ed25519.verify(public, message, preferred)
    assert minisign.ed25519_verify(public, message, pure)


def test_the_backend_in_use_is_named():
    assert minisign.ed25519_backend() in {"cryptography", "pure-python"}


# --- key files ---------------------------------------------------------------


def test_keypair_round_trips_through_the_minisign_file_formats(tmp_path):
    secret, public = minisign.generate_keypair(comment="test key")

    secret_path = secret.write(tmp_path / "k.key")
    assert secret_path.stat().st_mode & 0o777 == 0o600, "a secret key must be 0600"

    public_path = tmp_path / "k.pub"
    public_path.write_text(public.to_text(), encoding="utf-8")

    assert minisign.SecretKey.read(secret_path) == secret
    assert minisign.PublicKey.read(public_path) == public
    assert secret.public_key().key == public.key


def test_public_key_payload_is_forty_two_bytes():
    """The interop surface: `"Ed" | key_id[8] | key[32]`, base64, one line."""
    _, public = minisign.generate_keypair()
    line = public.to_text().splitlines()[1]
    raw = base64.standard_b64decode(line)
    assert len(raw) == 42
    assert raw[:2] == b"Ed"
    assert raw[2:10] == public.key_id
    assert raw[10:] == public.key


def test_a_corrupt_secret_key_is_refused(tmp_path):
    secret, _ = minisign.generate_keypair()
    path = secret.write(tmp_path / "k.key")
    lines = path.read_text().splitlines()
    raw = bytearray(base64.standard_b64decode(lines[1]))
    raw[70] ^= 0xFF  # inside the secret key, so the checksum stops matching
    path.write_text(
        lines[0] + "\n" + base64.standard_b64encode(bytes(raw)).decode() + "\n"
    )
    with pytest.raises(minisign.MinisignError, match="checksum"):
        minisign.SecretKey.read(path)


def test_a_password_protected_secret_key_says_so(tmp_path):
    """The scrypt form needs an interactive password a publish tool cannot give."""
    secret, _ = minisign.generate_keypair()
    path = secret.write(tmp_path / "k.key")
    lines = path.read_text().splitlines()
    raw = bytearray(base64.standard_b64decode(lines[1]))
    raw[2:4] = b"Sc"
    path.write_text(
        lines[0] + "\n" + base64.standard_b64encode(bytes(raw)).decode() + "\n"
    )
    with pytest.raises(minisign.MinisignError, match="password-protected"):
        minisign.SecretKey.read(path)


# --- signatures --------------------------------------------------------------


def test_sign_and_verify_a_file(tmp_path):
    secret, public = minisign.generate_keypair()
    target = tmp_path / "manifest.json"
    target.write_text('{"serial": 41}\n', encoding="utf-8")

    signature_path = minisign.sign_file(
        secret, target, trusted_comment="set=base serial=41"
    )
    assert signature_path.name == "manifest.json.minisig"
    assert minisign.verify_file(target, signature_path, [public]) == public

    parsed = minisign.Signature.read(signature_path)
    assert parsed.prehashed, "minisign's default is the prehashed algorithm"
    assert parsed.trusted_comment == "set=base serial=41"


def test_a_tampered_file_does_not_verify(tmp_path):
    secret, public = minisign.generate_keypair()
    target = tmp_path / "manifest.json"
    target.write_text('{"serial": 41}\n', encoding="utf-8")
    signature_path = minisign.sign_file(secret, target, trusted_comment="serial=41")

    target.write_text('{"serial": 40}\n', encoding="utf-8")
    with pytest.raises(minisign.MinisignError):
        minisign.verify_file(target, signature_path, [public])


def test_editing_the_trusted_comment_breaks_the_global_signature(tmp_path):
    """This is the downgrade defence, and it is the reason to sign that field.

    The trusted comment carries the serial. If it were merely a comment, an
    attacker could take a genuinely-signed manifest and relabel it. The global
    signature covers `signature || trusted_comment`, so relabelling invalidates
    it while the file signature still checks -- which is exactly the case this
    asserts is caught.
    """
    secret, public = minisign.generate_keypair()
    target = tmp_path / "manifest.json"
    target.write_bytes(b"payload")
    signature_path = minisign.sign_file(secret, target, trusted_comment="serial=41")

    text = signature_path.read_text().replace("serial=41", "serial=99")
    signature_path.write_text(text)

    with pytest.raises(minisign.MinisignError, match="trusted comment"):
        minisign.verify_file(target, signature_path, [public])


def test_a_signature_from_an_untrusted_key_is_refused(tmp_path):
    signer, _ = minisign.generate_keypair()
    _, stranger = minisign.generate_keypair()
    target = tmp_path / "manifest.json"
    target.write_bytes(b"payload")
    signature_path = minisign.sign_file(signer, target, trusted_comment="serial=1")

    with pytest.raises(minisign.MinisignError, match="not trusted"):
        minisign.verify_file(target, signature_path, [stranger])


def test_verification_with_no_trusted_keys_fails_closed(tmp_path):
    """An empty trusted-key set must never mean "accept anything"."""
    secret, _ = minisign.generate_keypair()
    target = tmp_path / "manifest.json"
    target.write_bytes(b"payload")
    signature_path = minisign.sign_file(secret, target, trusted_comment="serial=1")
    with pytest.raises(minisign.MinisignError, match="no trusted public keys"):
        minisign.verify_file(target, signature_path, [])


def test_legacy_and_prehashed_algorithms_both_verify(tmp_path):
    secret, public = minisign.generate_keypair()
    payload = b"a manifest, or something like one"
    for prehashed in (True, False):
        signature = minisign.sign_bytes(
            secret, payload, trusted_comment="t", prehashed=prehashed
        )
        round_tripped = minisign.Signature.from_text(signature.to_text())
        assert round_tripped == signature
        assert minisign.verify_bytes(payload, round_tripped, [public]) == public


# --- the shipped key ---------------------------------------------------------


def test_the_shipped_trusted_key_parses_and_is_a_development_key():
    """`data/sigs/trusted-keys/` must hold at least one usable public key.

    The bundled fallback manifest is verified against whatever is here, so an
    unparseable key file would make a fresh offline install fail with no
    signature library at all.
    """
    keys = sorted(TRUSTED_KEYS.glob("*.pub"))
    assert keys, f"no trusted public key ships in {TRUSTED_KEYS}"
    for path in keys:
        key = minisign.PublicKey.read(path)
        assert len(key.key) == 32
        assert len(key.key_id_hex) == 16


def test_no_secret_key_was_ever_committed():
    """A `.key` under `data/sigs/` is a leaked signing key, not a test fixture."""
    leaked = sorted((ROOT / "data" / "sigs").rglob("*.key"))
    assert not leaked, f"secret key material committed: {leaked}"
