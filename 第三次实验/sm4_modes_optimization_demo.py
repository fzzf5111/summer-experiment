"""SM4 software optimization and mode-of-operation demo.

The script is intentionally dependency-free.  It contains a scalar SM4
reference implementation, a T-table round function, a shuffle-style S-box
model, and CTR/GCM/XTS mode code built on top of the block cipher.
"""

from __future__ import annotations

from hmac import compare_digest
from time import perf_counter


MASK32 = 0xFFFFFFFF
MASK128 = (1 << 128) - 1
BLOCK_SIZE = 16

FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
CK = [
    0x00070E15,
    0x1C232A31,
    0x383F464D,
    0x545B6269,
    0x70777E85,
    0x8C939AA1,
    0xA8AFB6BD,
    0xC4CBD2D9,
    0xE0E7EEF5,
    0xFC030A11,
    0x181F262D,
    0x343B4249,
    0x50575E65,
    0x6C737A81,
    0x888F969D,
    0xA4ABB2B9,
    0xC0C7CED5,
    0xDCE3EAF1,
    0xF8FF060D,
    0x141B2229,
    0x30373E45,
    0x4C535A61,
    0x686F767D,
    0x848B9299,
    0xA0A7AEB5,
    0xBCC3CAD1,
    0xD8DFE6ED,
    0xF4FB0209,
    0x10171E25,
    0x2C333A41,
    0x484F565D,
    0x646B7279,
]

SBOX = [
    0xD6,
    0x90,
    0xE9,
    0xFE,
    0xCC,
    0xE1,
    0x3D,
    0xB7,
    0x16,
    0xB6,
    0x14,
    0xC2,
    0x28,
    0xFB,
    0x2C,
    0x05,
    0x2B,
    0x67,
    0x9A,
    0x76,
    0x2A,
    0xBE,
    0x04,
    0xC3,
    0xAA,
    0x44,
    0x13,
    0x26,
    0x49,
    0x86,
    0x06,
    0x99,
    0x9C,
    0x42,
    0x50,
    0xF4,
    0x91,
    0xEF,
    0x98,
    0x7A,
    0x33,
    0x54,
    0x0B,
    0x43,
    0xED,
    0xCF,
    0xAC,
    0x62,
    0xE4,
    0xB3,
    0x1C,
    0xA9,
    0xC9,
    0x08,
    0xE8,
    0x95,
    0x80,
    0xDF,
    0x94,
    0xFA,
    0x75,
    0x8F,
    0x3F,
    0xA6,
    0x47,
    0x07,
    0xA7,
    0xFC,
    0xF3,
    0x73,
    0x17,
    0xBA,
    0x83,
    0x59,
    0x3C,
    0x19,
    0xE6,
    0x85,
    0x4F,
    0xA8,
    0x68,
    0x6B,
    0x81,
    0xB2,
    0x71,
    0x64,
    0xDA,
    0x8B,
    0xF8,
    0xEB,
    0x0F,
    0x4B,
    0x70,
    0x56,
    0x9D,
    0x35,
    0x1E,
    0x24,
    0x0E,
    0x5E,
    0x63,
    0x58,
    0xD1,
    0xA2,
    0x25,
    0x22,
    0x7C,
    0x3B,
    0x01,
    0x21,
    0x78,
    0x87,
    0xD4,
    0x00,
    0x46,
    0x57,
    0x9F,
    0xD3,
    0x27,
    0x52,
    0x4C,
    0x36,
    0x02,
    0xE7,
    0xA0,
    0xC4,
    0xC8,
    0x9E,
    0xEA,
    0xBF,
    0x8A,
    0xD2,
    0x40,
    0xC7,
    0x38,
    0xB5,
    0xA3,
    0xF7,
    0xF2,
    0xCE,
    0xF9,
    0x61,
    0x15,
    0xA1,
    0xE0,
    0xAE,
    0x5D,
    0xA4,
    0x9B,
    0x34,
    0x1A,
    0x55,
    0xAD,
    0x93,
    0x32,
    0x30,
    0xF5,
    0x8C,
    0xB1,
    0xE3,
    0x1D,
    0xF6,
    0xE2,
    0x2E,
    0x82,
    0x66,
    0xCA,
    0x60,
    0xC0,
    0x29,
    0x23,
    0xAB,
    0x0D,
    0x53,
    0x4E,
    0x6F,
    0xD5,
    0xDB,
    0x37,
    0x45,
    0xDE,
    0xFD,
    0x8E,
    0x2F,
    0x03,
    0xFF,
    0x6A,
    0x72,
    0x6D,
    0x6C,
    0x5B,
    0x51,
    0x8D,
    0x1B,
    0xAF,
    0x92,
    0xBB,
    0xDD,
    0xBC,
    0x7F,
    0x11,
    0xD9,
    0x5C,
    0x41,
    0x1F,
    0x10,
    0x5A,
    0xD8,
    0x0A,
    0xC1,
    0x31,
    0x88,
    0xA5,
    0xCD,
    0x7B,
    0xBD,
    0x2D,
    0x74,
    0xD0,
    0x12,
    0xB8,
    0xE5,
    0xB4,
    0xB0,
    0x89,
    0x69,
    0x97,
    0x4A,
    0x0C,
    0x96,
    0x77,
    0x7E,
    0x65,
    0xB9,
    0xF1,
    0x09,
    0xC5,
    0x6E,
    0xC6,
    0x84,
    0x18,
    0xF0,
    0x7D,
    0xEC,
    0x3A,
    0xDC,
    0x4D,
    0x20,
    0x79,
    0xEE,
    0x5F,
    0x3E,
    0xD7,
    0xCB,
    0x39,
    0x48,
]

SBOX_ROWS = tuple(bytes(SBOX[i : i + 16]) for i in range(0, 256, 16))


def rotl32(value: int, shift: int) -> int:
    value &= MASK32
    return ((value << shift) | (value >> (32 - shift))) & MASK32


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def bytes_to_u32s(block: bytes) -> list[int]:
    return [int.from_bytes(block[i : i + 4], "big") for i in range(0, len(block), 4)]


def u32s_to_bytes(words: list[int]) -> bytes:
    return b"".join((word & MASK32).to_bytes(4, "big") for word in words)


def sm4_tau(word: int) -> int:
    return (
        (SBOX[(word >> 24) & 0xFF] << 24)
        | (SBOX[(word >> 16) & 0xFF] << 16)
        | (SBOX[(word >> 8) & 0xFF] << 8)
        | SBOX[word & 0xFF]
    )


def sm4_l(word: int) -> int:
    return word ^ rotl32(word, 2) ^ rotl32(word, 10) ^ rotl32(word, 18) ^ rotl32(word, 24)


def sm4_l_key(word: int) -> int:
    return word ^ rotl32(word, 13) ^ rotl32(word, 23)


def sm4_t_slow(word: int) -> int:
    return sm4_l(sm4_tau(word))


def sm4_t_key(word: int) -> int:
    return sm4_l_key(sm4_tau(word))


def build_t_table(byte_position: int) -> tuple[int, ...]:
    shift = 24 - 8 * byte_position
    return tuple(sm4_l(SBOX[value] << shift) for value in range(256))


T_TABLES = tuple(build_t_table(pos) for pos in range(4))


def sm4_t_table(word: int) -> int:
    return (
        T_TABLES[0][(word >> 24) & 0xFF]
        ^ T_TABLES[1][(word >> 16) & 0xFF]
        ^ T_TABLES[2][(word >> 8) & 0xFF]
        ^ T_TABLES[3][word & 0xFF]
    )


def sbox_shuffle_bytes(data: bytes) -> bytes:
    """Emulate the shape of a nibble-based SIMD shuffle S-box lookup."""
    return bytes(SBOX_ROWS[value >> 4][value & 0x0F] for value in data)


def sm4_t_shuffle(word: int) -> int:
    substituted = int.from_bytes(sbox_shuffle_bytes(word.to_bytes(4, "big")), "big")
    return sm4_l(substituted)


def sm4_key_schedule(key: bytes) -> list[int]:
    if len(key) != BLOCK_SIZE:
        raise ValueError("SM4 key must be 16 bytes")

    mk = bytes_to_u32s(key)
    k = [mk[i] ^ FK[i] for i in range(4)]
    round_keys = []
    for i in range(32):
        next_key = k[i] ^ sm4_t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i])
        k.append(next_key)
        round_keys.append(next_key)
    return round_keys


def sm4_crypt_block(block: bytes, round_keys: list[int], transform=sm4_t_slow) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("SM4 block must be 16 bytes")

    x = bytes_to_u32s(block)
    for i in range(32):
        x.append(x[i] ^ transform(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ round_keys[i]))
    return u32s_to_bytes([x[35], x[34], x[33], x[32]])


def sm4_encrypt_block(block: bytes, key: bytes, transform=sm4_t_table) -> bytes:
    return sm4_crypt_block(block, sm4_key_schedule(key), transform)


def sm4_decrypt_block(block: bytes, key: bytes, transform=sm4_t_table) -> bytes:
    return sm4_crypt_block(block, list(reversed(sm4_key_schedule(key))), transform)


def inc128(counter: int) -> int:
    return (counter + 1) & MASK128


def inc32(counter: int) -> int:
    low = (counter + 1) & 0xFFFFFFFF
    return (counter & (MASK128 ^ 0xFFFFFFFF)) | low


def sm4_ctr_crypt(data: bytes, key: bytes, iv: bytes, transform=sm4_t_table, increment=inc128) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CTR IV must be 16 bytes")

    round_keys = sm4_key_schedule(key)
    counter = int.from_bytes(iv, "big")
    output = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        keystream = sm4_crypt_block(counter.to_bytes(BLOCK_SIZE, "big"), round_keys, transform)
        block = data[offset : offset + BLOCK_SIZE]
        output.extend(xor_bytes(block, keystream[: len(block)]))
        counter = increment(counter)
    return bytes(output)


GCM_R = 0xE1000000000000000000000000000000


def gf_mul_bitwise(x: int, y: int) -> int:
    z = 0
    v = y
    for bit_index in range(128):
        if (x >> (127 - bit_index)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ GCM_R
        else:
            v >>= 1
    return z & MASK128


def build_ghash_4bit_tables(h: int) -> list[list[int]]:
    tables: list[list[int]] = []
    for pos in range(32):
        shift = 124 - 4 * pos
        tables.append([gf_mul_bitwise(nibble << shift, h) for nibble in range(16)])
    return tables


def gf_mul_4bit(x: int, tables: list[list[int]]) -> int:
    result = 0
    for pos in range(32):
        result ^= tables[pos][(x >> (124 - 4 * pos)) & 0x0F]
    return result & MASK128


def iter_padded_blocks(data: bytes):
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        yield block.ljust(BLOCK_SIZE, b"\x00")
    if not data:
        return


def ghash(aad: bytes, ciphertext: bytes, h: int, use_4bit_table: bool = True) -> int:
    y = 0
    tables = build_ghash_4bit_tables(h) if use_4bit_table else None

    def multiply(value: int) -> int:
        if tables is None:
            return gf_mul_bitwise(value, h)
        return gf_mul_4bit(value, tables)

    for block in iter_padded_blocks(aad):
        y = multiply(y ^ int.from_bytes(block, "big"))
    for block in iter_padded_blocks(ciphertext):
        y = multiply(y ^ int.from_bytes(block, "big"))

    length_block = (len(aad) * 8).to_bytes(8, "big") + (len(ciphertext) * 8).to_bytes(8, "big")
    return multiply(y ^ int.from_bytes(length_block, "big"))


def gcm_j0(iv: bytes, h: int) -> int:
    if len(iv) == 12:
        return int.from_bytes(iv + b"\x00\x00\x00\x01", "big")
    return ghash(b"", iv, h)


def sm4_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    aad: bytes = b"",
    transform=sm4_t_table,
) -> tuple[bytes, bytes]:
    round_keys = sm4_key_schedule(key)
    h = int.from_bytes(sm4_crypt_block(b"\x00" * BLOCK_SIZE, round_keys, transform), "big")
    j0 = gcm_j0(iv, h)
    ciphertext = sm4_ctr_crypt(plaintext, key, inc32(j0).to_bytes(BLOCK_SIZE, "big"), transform, inc32)
    auth_value = ghash(aad, ciphertext, h)
    tag_mask = sm4_crypt_block(j0.to_bytes(BLOCK_SIZE, "big"), round_keys, transform)
    tag = (int.from_bytes(tag_mask, "big") ^ auth_value).to_bytes(BLOCK_SIZE, "big")
    return ciphertext, tag


def sm4_gcm_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    tag: bytes,
    aad: bytes = b"",
    transform=sm4_t_table,
) -> bytes:
    round_keys = sm4_key_schedule(key)
    h = int.from_bytes(sm4_crypt_block(b"\x00" * BLOCK_SIZE, round_keys, transform), "big")
    j0 = gcm_j0(iv, h)
    auth_value = ghash(aad, ciphertext, h)
    tag_mask = sm4_crypt_block(j0.to_bytes(BLOCK_SIZE, "big"), round_keys, transform)
    expected_tag = (int.from_bytes(tag_mask, "big") ^ auth_value).to_bytes(BLOCK_SIZE, "big")
    if not compare_digest(expected_tag, tag):
        raise ValueError("GCM tag verification failed")
    return sm4_ctr_crypt(ciphertext, key, inc32(j0).to_bytes(BLOCK_SIZE, "big"), transform, inc32)


def xts_mul_alpha(tweak: bytes) -> bytes:
    value = int.from_bytes(tweak, "big")
    carry = value >> 127
    value = ((value << 1) & MASK128) ^ (0x87 if carry else 0)
    return value.to_bytes(BLOCK_SIZE, "big")


def sm4_xts_crypt_full_blocks(
    data: bytes,
    data_key: bytes,
    tweak_key: bytes,
    tweak_value: bytes,
    decrypt: bool = False,
    transform=sm4_t_table,
) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("this compact XTS demo expects full 16-byte blocks")
    if len(tweak_value) != BLOCK_SIZE:
        raise ValueError("XTS tweak value must be 16 bytes")

    data_round_keys = sm4_key_schedule(data_key)
    if decrypt:
        data_round_keys = list(reversed(data_round_keys))
    tweak = sm4_encrypt_block(tweak_value, tweak_key, transform)
    output = bytearray()
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        mixed = xor_bytes(block, tweak)
        crypted = sm4_crypt_block(mixed, data_round_keys, transform)
        output.extend(xor_bytes(crypted, tweak))
        tweak = xts_mul_alpha(tweak)
    return bytes(output)


def check_sm4_vectors() -> None:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    plain = bytes.fromhex("0123456789abcdeffedcba9876543210")
    expected = bytes.fromhex("681edf34d206965e86b3e94f536e4246")
    round_keys = sm4_key_schedule(key)

    for name, transform in [
        ("basic", sm4_t_slow),
        ("t-table", sm4_t_table),
        ("shuffle-model", sm4_t_shuffle),
    ]:
        cipher = sm4_crypt_block(plain, round_keys, transform)
        recovered = sm4_decrypt_block(cipher, key, transform)
        assert cipher == expected, name
        assert recovered == plain, name


def benchmark_block_variants() -> None:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    round_keys = sm4_key_schedule(key)
    blocks = [i.to_bytes(16, "big") for i in range(2048)]
    print("SM4 block benchmark, 2048 blocks")
    for name, transform in [
        ("basic round", sm4_t_slow),
        ("T-table round", sm4_t_table),
        ("shuffle model", sm4_t_shuffle),
    ]:
        start = perf_counter()
        checksum = 0
        for block in blocks:
            checksum ^= sm4_crypt_block(block, round_keys, transform)[0]
        elapsed = perf_counter() - start
        mib = len(blocks) * BLOCK_SIZE / (1024 * 1024)
        print(f"  {name:14s}: {elapsed:.4f}s, {mib / elapsed:.2f} MiB/s, checksum={checksum:02x}")


def demo_modes() -> None:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    key2 = bytes.fromhex("fedcba98765432100123456789abcdef")
    ctr_iv = bytes.fromhex("0000000000000000000000000000002a")
    gcm_iv = bytes.fromhex("00112233445566778899aabb")
    xts_tweak = bytes.fromhex("11223344556677889900aabbccddeeff")
    aad = b"summer experiment aad"
    plaintext = (b"SM4 optimized software modes demo block. " * 6)[:192]

    ctr_ciphertext = sm4_ctr_crypt(plaintext, key, ctr_iv)
    assert sm4_ctr_crypt(ctr_ciphertext, key, ctr_iv) == plaintext

    gcm_ciphertext, gcm_tag = sm4_gcm_encrypt(plaintext, key, gcm_iv, aad)
    assert sm4_gcm_decrypt(gcm_ciphertext, key, gcm_iv, gcm_tag, aad) == plaintext

    xts_plaintext = plaintext[:128]
    xts_ciphertext = sm4_xts_crypt_full_blocks(xts_plaintext, key, key2, xts_tweak)
    assert sm4_xts_crypt_full_blocks(xts_ciphertext, key, key2, xts_tweak, decrypt=True) == xts_plaintext

    print("Mode round-trip checks")
    print(f"  CTR ciphertext prefix : {ctr_ciphertext[:16].hex()}")
    print(f"  GCM tag               : {gcm_tag.hex()}")
    print(f"  XTS ciphertext prefix : {xts_ciphertext[:16].hex()}")


def print_instruction_mapping() -> None:
    print("Instruction-set mapping represented by this Python model")
    print("  x86 AVX2/AVX-512 : VPSHUFB-style S-box shuffle, vector lanes for CTR/XTS")
    print("  x86 VAES+PCLMUL  : AES/GCM analogue; VPCLMULQDQ maps to GHASH carry-less multiply")
    print("  ARMv8.4-A SM4    : SM4E/SM4EKEY for rounds and PMULL for GHASH")


def main() -> None:
    check_sm4_vectors()
    print("SM4 official test vector: ok")
    print_instruction_mapping()
    demo_modes()
    benchmark_block_variants()


if __name__ == "__main__":
    main()
