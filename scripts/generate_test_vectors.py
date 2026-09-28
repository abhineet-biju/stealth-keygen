#!/usr/bin/env python3
"""Generate public test fixtures independently of the Rust implementation.

Uses only Python's standard library and the affine Edwards / Montgomery
formulas from RFC 8032 and RFC 7748. This is slow, variable-time TEST CODE,
not a signing implementation for real keys. All input secrets are public.

Run from any directory: python3 scripts/generate_test_vectors.py
Inspect fixture changes; do not regenerate expectations to silence a test.
"""

import hashlib
import hmac
from pathlib import Path

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
G = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def add(a, b):
    x, y = a
    u, v = b
    z = D * x * u * y * v % P
    return ((x * v + y * u) * pow(1 + z, -1, P) % P,
            (y * v + x * u) * pow(1 - z, -1, P) % P)


def mul(n, point=G):
    result = (0, 1)
    while n:
        if n & 1:
            result = add(result, point)
        point = add(point, point)
        n >>= 1
    return result


def encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def x25519(raw, public=bytes([9]) + bytes(31)):
    k = bytearray(raw)
    k[0] &= 248
    k[31] = (k[31] & 127) | 64
    k = int.from_bytes(k, "little")
    x1 = int.from_bytes(public, "little") & (2**255 - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit in range(254, -1, -1):
        kt = (k >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % P, (x2 - z2) % P
        aa, bb = a * a % P, b * b % P
        e = (aa - bb) % P
        c, d = (x3 + z3) % P, (x3 - z3) % P
        da, cb = d * a % P, c * b % P
        x3, z3 = (da + cb)**2 % P, x1 * (da - cb)**2 % P
        x2, z2 = aa * bb % P, e * (aa + 121665 * e) % P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def sign(scalar, prefix, message):
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_pub, pub = encode(mul(r)), encode(mul(scalar))
    challenge = int.from_bytes(hashlib.sha512(r_pub + pub + message).digest(), "little") % L
    return r_pub + ((r + challenge * scalar) % L).to_bytes(32, "little")


def check_reference_math():
    # RFC 7748 section 6.1.
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert x25519(a, b_pub).hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    # RFC 8032 section 7.1, TEST 1: empty message.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    expanded = hashlib.sha512(seed).digest()
    a = bytearray(expanded[:32])
    a[0] &= 248
    a[31] = (a[31] & 63) | 64
    scalar = int.from_bytes(a, "little")
    assert encode(mul(scalar)).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert sign(scalar, expanded[32:], b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


def hkdf_sha256(ikm, salt, info, length):
    """RFC 5869 extract/expand, implemented separately from RustCrypto."""
    if not 0 <= length <= 255 * 32:
        raise ValueError("invalid HKDF output length")
    prk = hmac.digest(salt, ikm, "sha256")
    previous, output = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        output += previous
    return prk, output[:length]


def check_hkdf_reference():
    # RFC 5869 appendix A.1.
    prk, output = hkdf_sha256(bytes([0x0b])*22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert output.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            "34007208d5b887185865")


def main():
    check_reference_math()
    check_hkdf_reference()
    spend_entropy, scan_entropy, ephemeral_entropy = bytes([1])*64, bytes([2])*32, bytes([3])*32
    spend = int.from_bytes(spend_entropy, "little") % L
    scan_public, ephemeral_public = x25519(scan_entropy), x25519(ephemeral_entropy)
    shared = x25519(ephemeral_entropy, scan_public)
    assert shared == x25519(scan_entropy, ephemeral_public)
    salt = b"stealth-keygen-v2"
    prk, tag = hkdf_sha256(shared, salt, b"discovery-tag", 1)
    _, wide = hkdf_sha256(shared, salt, b"spend-tweak", 64)
    tweak = int.from_bytes(wide, "little") % L
    payment_scalar = (spend + tweak) % L
    nonce_domain = b"stealth-keygen-v1-nonce"
    prefix = hashlib.sha512(bytes([len(nonce_domain)]) + nonce_domain + payment_scalar.to_bytes(32, "little")).digest()[32:]
    message = b"stealth-keygen test vector"
    values = {
        "spend_entropy": spend_entropy,
        "scan_entropy": scan_entropy,
        "ephemeral_entropy": ephemeral_entropy,
        "spend_public": encode(mul(spend)),
        "scan_public": scan_public,
        "ephemeral_public": ephemeral_public,
        "shared_secret": shared,
        "discovery_tag": tag,
        "tweak": tweak.to_bytes(32, "little"),
        "payment_scalar": payment_scalar.to_bytes(32, "little"),
        "payment_public": encode(mul(payment_scalar)),
        "message": message,
        "signature": sign(payment_scalar, prefix, message),
        "hkdf_prk": prk,
        "tweak_material": wide,
    }
    # Fixed public context: chain ID, application program, mint, token account.
    context = bytes([1])*32 + bytes([2])*32 + bytes([3])*32 + bytes([4])*32
    _, elgamal_wide = hkdf_sha256(shared, salt, b"elgamal-key-v1" + context, 64)
    elgamal_scalar = int.from_bytes(elgamal_wide, "little") % L
    assert elgamal_scalar != 0
    values["elgamal_context"] = context
    values["elgamal_material"] = elgamal_wide
    values["elgamal_scalar"] = elgamal_scalar.to_bytes(32, "little")
    out = Path(__file__).resolve().parents[1] / "tests/fixtures/hkdf.txt"
    out.write_text("# Public test inputs only. Generated by scripts/generate_test_vectors.py.\n" +
                   "".join(f"{key}={value.hex()}\n" for key, value in values.items()))
    print(f"Verified RFC vectors and wrote {out}")


if __name__ == "__main__":
    main()
