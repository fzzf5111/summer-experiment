"""ECDSA hash-binding pitfall demo on secp256k1.

This program demonstrates the construction described in the report:
if a verifier accepts an attacker-supplied message hash e instead of computing
e = H(message) itself, the attacker can create a valid ECDSA signature for
some e without knowing the private key.
"""

from __future__ import annotations

from hashlib import sha256


P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
INF = None


def inverse_mod(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def point_add(point_a, point_b):
    if point_a is INF:
        return point_b
    if point_b is INF:
        return point_a

    x1, y1 = point_a
    x2, y2 = point_b

    if x1 == x2 and (y1 + y2) % P_FIELD == 0:
        return INF

    if point_a == point_b:
        slope = (3 * x1 * x1) * inverse_mod(2 * y1, P_FIELD)
    else:
        slope = (y2 - y1) * inverse_mod(x2 - x1, P_FIELD)

    slope %= P_FIELD
    x3 = (slope * slope - x1 - x2) % P_FIELD
    y3 = (slope * (x1 - x3) - y1) % P_FIELD
    return x3, y3


def scalar_mult(k: int, point):
    result = INF
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def ecdsa_verify(public_key, msg_hash: int, signature: tuple[int, int]) -> bool:
    r, s = signature
    if not (1 <= r < N_ORDER and 1 <= s < N_ORDER):
        return False

    w = inverse_mod(s, N_ORDER)
    u1 = (msg_hash * w) % N_ORDER
    u2 = (r * w) % N_ORDER
    x = point_add(scalar_mult(u1, G), scalar_mult(u2, public_key))
    return x is not INF and x[0] % N_ORDER == r


def forge_signature_for_hash(public_key, u: int, v: int) -> tuple[int, tuple[int, int]]:
    r_point = point_add(scalar_mult(u, G), scalar_mult(v, public_key))
    if r_point is INF:
        raise ValueError("invalid chosen u/v values")

    r = r_point[0] % N_ORDER
    if r == 0:
        raise ValueError("r became zero; choose other u/v values")

    v_inv = inverse_mod(v, N_ORDER)
    s = (r * v_inv) % N_ORDER
    forged_hash = (r * u * v_inv) % N_ORDER
    return forged_hash, (r, s)


def hash_message(message: bytes) -> int:
    return int.from_bytes(sha256(message).digest(), "big") % N_ORDER


def main() -> None:
    private_key = 0x1DCE8D2EC6184CAF0A972AD327B566A9DB62D1E5F942FE3A78F1DA040BA4E0A9
    public_key = scalar_mult(private_key, G)

    attacker_u = 0xA3F7C9D68127
    attacker_v = 0xD92B4E71135B
    forged_hash, signature = forge_signature_for_hash(public_key, attacker_u, attacker_v)

    claimed_message = b"pay 1 BTC to attacker"
    real_hash = hash_message(claimed_message)

    print("public key x =", hex(public_key[0]))
    print("public key y =", hex(public_key[1]))
    print("forged e'    =", hex(forged_hash))
    print("r            =", hex(signature[0]))
    print("s            =", hex(signature[1]))
    print()
    print("verify(signature, attacker supplied e') =", ecdsa_verify(public_key, forged_hash, signature))
    print("verify(signature, H(claimed message))   =", ecdsa_verify(public_key, real_hash, signature))


if __name__ == "__main__":
    main()
