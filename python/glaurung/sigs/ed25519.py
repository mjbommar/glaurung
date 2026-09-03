"""Ed25519 signing and verification with no third-party dependency.

Why this file exists
--------------------

Signature-set distribution has to verify a minisign signature at *fetch*
time, which is the moment a fresh `pip install glaurung` first touches the
network. `cryptography` is present in `uv.lock` (49.0.0) but only
transitively, via `authlib` -> `pydantic-ai`; it is not declared in
`[project].dependencies`, so nothing guarantees it is importable in an
installed wheel. A verifier that is sometimes absent is not a verifier: the
fetch path would have to either fail or skip the check, and skipping is how
an unsigned manifest gets accepted.

So :func:`verify` and :func:`sign` here are the floor, and
:mod:`glaurung.sigs.minisign` prefers `cryptography` when it *is* importable
(it is a C implementation, and constant-time where this one is not). The two
backends are cross-checked against each other in
`python/tests/test_sigs_minisign.py`.

This is the RFC 8032 section 6 reference construction: birationally
equivalent twisted Edwards curve arithmetic in extended homogeneous
coordinates `(X, Y, Z, T)`, SHA-512 for both the key expansion and the
challenge. It is *not* constant time and must never be used for a long-lived
online signing key; the only secret it handles here is the release-signing
key on a maintainer's own machine, and the operation that runs on user
machines is verification, which handles no secret at all.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "PUBLIC_KEY_BYTES",
    "SECRET_KEY_BYTES",
    "SEED_BYTES",
    "SIGNATURE_BYTES",
    "public_from_seed",
    "sign",
    "verify",
]

#: Byte widths of the RFC 8032 objects, so callers can validate without
#: repeating magic numbers. `SECRET_KEY_BYTES` is libsodium's convention,
#: which minisign inherits: the 32-byte seed followed by the 32-byte public
#: key, so a signer never has to re-derive the public half.
SEED_BYTES = 32
PUBLIC_KEY_BYTES = 32
SECRET_KEY_BYTES = 64
SIGNATURE_BYTES = 64

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign_bit: int) -> int | None:
    """The curve point's x for a given y and sign bit, or None if off-curve."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign_bit else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign_bit:
        x = _P - x
    return x


_G_Y = 4 * _inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None  # the base point is a compile-time constant of the curve
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)

#: The neutral element in extended coordinates.
_IDENTITY = (0, 1, 1, 0)

_Point = tuple[int, int, int, int]


def _add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    dd = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p: _Point, q: _Point) -> bool:
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(point: _Point) -> bytes:
    zinv = _inv(point[2])
    x = point[0] * zinv % _P
    y = point[1] * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data: bytes) -> _Point | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign_bit = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign_bit)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _expand(seed: bytes) -> tuple[int, bytes]:
    """Clamp the SHA-512 of the seed into a scalar plus the prefix half."""
    digest = _sha512(seed)
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_from_seed(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed."""
    if len(seed) != SEED_BYTES:
        raise ValueError(f"seed must be {SEED_BYTES} bytes, got {len(seed)}")
    scalar, _ = _expand(seed)
    return _compress(_mul(scalar, _G))


def sign(seed: bytes, message: bytes) -> bytes:
    """A 64-byte Ed25519 signature over `message` under the key from `seed`."""
    if len(seed) != SEED_BYTES:
        raise ValueError(f"seed must be {SEED_BYTES} bytes, got {len(seed)}")
    scalar, prefix = _expand(seed)
    public = _compress(_mul(scalar, _G))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    big_r = _compress(_mul(r, _G))
    challenge = int.from_bytes(_sha512(big_r + public + message), "little") % _L
    s = (r + challenge * scalar) % _L
    return big_r + int.to_bytes(s, 32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` is a valid Ed25519 signature. Never raises."""
    if len(public_key) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    point_a = _decompress(public_key)
    if point_a is None:
        return False
    point_r = _decompress(signature[:32])
    if point_r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    # RFC 8032 requires the scalar to be canonical; a non-reduced `s` is how
    # signature malleability gets in.
    if s >= _L:
        return False
    challenge = int.from_bytes(_sha512(signature[:32] + public_key + message), "little")
    return _equal(_mul(s, _G), _add(point_r, _mul(challenge % _L, point_a)))
