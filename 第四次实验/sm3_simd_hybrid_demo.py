"""SM3 scalar and SIMD-hybrid software implementation demo.

The SIMD part is a portable Python model: each list represents a SIMD register
whose elements are 32-bit lanes.  It verifies the same data flow used by an
ARM64 NEON, x86 AVX2, or x86 AVX-512 multi-buffer SM3 implementation.
"""

from __future__ import annotations

from time import perf_counter


MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 64

IV = [
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
]

T0 = 0x79CC4519
T1 = 0x7A879D8A


def rotl32(value: int, shift: int) -> int:
    value &= MASK32
    shift &= 31
    return ((value << shift) | (value >> (32 - shift))) & MASK32


def p0(value: int) -> int:
    return value ^ rotl32(value, 9) ^ rotl32(value, 17)


def p1(value: int) -> int:
    return value ^ rotl32(value, 15) ^ rotl32(value, 23)


def ff(x: int, y: int, z: int, round_index: int) -> int:
    if round_index < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def gg(x: int, y: int, z: int, round_index: int) -> int:
    if round_index < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & MASK32) & z)


def sm3_pad(message: bytes) -> bytes:
    bit_length = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while (len(padded) % BLOCK_SIZE) != 56:
        padded.append(0)
    padded.extend(bit_length.to_bytes(8, "big"))
    return bytes(padded)


def words_from_block(block: bytes) -> list[int]:
    return [int.from_bytes(block[i : i + 4], "big") for i in range(0, BLOCK_SIZE, 4)]


def sm3_compress_scalar(state: list[int], block: bytes) -> list[int]:
    w = words_from_block(block)
    for j in range(16, 68):
        value = p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15))
        value ^= rotl32(w[j - 13], 7) ^ w[j - 6]
        w.append(value & MASK32)
    w1 = [(w[j] ^ w[j + 4]) & MASK32 for j in range(64)]

    a, b, c, d, e, f, g, h = state
    for j in range(64):
        tj = T0 if j < 16 else T1
        ss1 = rotl32((rotl32(a, 12) + e + rotl32(tj, j % 32)) & MASK32, 7)
        ss2 = ss1 ^ rotl32(a, 12)
        tt1 = (ff(a, b, c, j) + d + ss2 + w1[j]) & MASK32
        tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & MASK32
        d = c
        c = rotl32(b, 9)
        b = a
        a = tt1
        h = g
        g = rotl32(f, 19)
        f = e
        e = p0(tt2)

    return [
        a ^ state[0],
        b ^ state[1],
        c ^ state[2],
        d ^ state[3],
        e ^ state[4],
        f ^ state[5],
        g ^ state[6],
        h ^ state[7],
    ]


def sm3_hash_scalar(message: bytes) -> bytes:
    state = IV[:]
    padded = sm3_pad(message)
    for offset in range(0, len(padded), BLOCK_SIZE):
        state = sm3_compress_scalar(state, padded[offset : offset + BLOCK_SIZE])
    return b"".join(word.to_bytes(4, "big") for word in state)


def vxor(left: list[int], right: list[int]) -> list[int]:
    return [(a ^ b) & MASK32 for a, b in zip(left, right)]


def vxor3(a: list[int], b: list[int], c: list[int]) -> list[int]:
    return [(x ^ y ^ z) & MASK32 for x, y, z in zip(a, b, c)]


def vand(left: list[int], right: list[int]) -> list[int]:
    return [(a & b) & MASK32 for a, b in zip(left, right)]


def vor(left: list[int], right: list[int]) -> list[int]:
    return [(a | b) & MASK32 for a, b in zip(left, right)]


def vnot(values: list[int]) -> list[int]:
    return [(~value) & MASK32 for value in values]


def vrotl(values: list[int], shift: int) -> list[int]:
    return [rotl32(value, shift) for value in values]


def vp0(values: list[int]) -> list[int]:
    return [p0(value) for value in values]


def vp1(values: list[int]) -> list[int]:
    return [p1(value) for value in values]


def vadd4(a: list[int], b: list[int], c: list[int], d: list[int]) -> list[int]:
    return [(w + x + y + z) & MASK32 for w, x, y, z in zip(a, b, c, d)]


def vadd_scalar3(a: list[int], b: list[int], scalar: int) -> list[int]:
    return [(x + y + scalar) & MASK32 for x, y in zip(a, b)]


def vff(x: list[int], y: list[int], z: list[int], round_index: int) -> list[int]:
    if round_index < 16:
        return vxor3(x, y, z)
    return vor(vor(vand(x, y), vand(x, z)), vand(y, z))


def vgg(x: list[int], y: list[int], z: list[int], round_index: int) -> list[int]:
    if round_index < 16:
        return vxor3(x, y, z)
    return vor(vand(x, y), vand(vnot(x), z))


def sm3_compress_simd(state: list[list[int]], block_words_by_lane: list[list[int]]) -> list[list[int]]:
    lanes = len(block_words_by_lane)
    w = [[block_words_by_lane[lane][j] for lane in range(lanes)] for j in range(16)]
    for j in range(16, 68):
        value = vp1(vxor3(w[j - 16], w[j - 9], vrotl(w[j - 3], 15)))
        value = vxor3(value, vrotl(w[j - 13], 7), w[j - 6])
        w.append(value)
    w1 = [vxor(w[j], w[j + 4]) for j in range(64)]

    old_state = [part[:] for part in state]
    a, b, c, d, e, f, g, h = [part[:] for part in state]

    for j in range(64):
        tj = T0 if j < 16 else T1
        a12 = vrotl(a, 12)
        ss1 = vrotl(vadd_scalar3(a12, e, rotl32(tj, j % 32)), 7)
        ss2 = vxor(ss1, a12)
        tt1 = vadd4(vff(a, b, c, j), d, ss2, w1[j])
        tt2 = vadd4(vgg(e, f, g, j), h, ss1, w[j])
        d = c
        c = vrotl(b, 9)
        b = a
        a = tt1
        h = g
        g = vrotl(f, 19)
        f = e
        e = vp0(tt2)

    return [
        vxor(a, old_state[0]),
        vxor(b, old_state[1]),
        vxor(c, old_state[2]),
        vxor(d, old_state[3]),
        vxor(e, old_state[4]),
        vxor(f, old_state[5]),
        vxor(g, old_state[6]),
        vxor(h, old_state[7]),
    ]


def sm3_hash_simd_group(messages: list[bytes]) -> list[bytes]:
    lanes = len(messages)
    padded_messages = [sm3_pad(message) for message in messages]
    lengths = {len(message) for message in padded_messages}
    if len(lengths) != 1:
        raise ValueError("SIMD group requires messages with the same padded length")

    state = [[word] * lanes for word in IV]
    block_count = len(padded_messages[0]) // BLOCK_SIZE
    for block_index in range(block_count):
        lane_words = []
        start = block_index * BLOCK_SIZE
        for lane in range(lanes):
            lane_words.append(words_from_block(padded_messages[lane][start : start + BLOCK_SIZE]))
        state = sm3_compress_simd(state, lane_words)

    digests = []
    for lane in range(lanes):
        digest = b"".join(state[word_index][lane].to_bytes(4, "big") for word_index in range(8))
        digests.append(digest)
    return digests


def sm3_hash_many_simd(messages: list[bytes], lanes: int) -> list[bytes]:
    output: list[bytes] = []
    for offset in range(0, len(messages), lanes):
        group = messages[offset : offset + lanes]
        if len(group) != lanes:
            output.extend(sm3_hash_scalar(message) for message in group)
            continue
        padded_lengths = {len(sm3_pad(message)) for message in group}
        if len(padded_lengths) != 1:
            output.extend(sm3_hash_scalar(message) for message in group)
            continue
        output.extend(sm3_hash_simd_group(group))
    return output


ARCHITECTURE_LANES = {
    "arm64-neon-128": 4,
    "x86-avx2-256": 8,
    "x86-avx512-512": 16,
}


def check_vectors() -> None:
    expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    digest = sm3_hash_scalar(b"abc").hex()
    assert digest == expected

    messages = [b"abc", b"abcd" * 16, b"message lane 02", b"message lane 03"]
    same_length = [b"parallel-sm3-lane-%02d" % index for index in range(4)]
    assert sm3_hash_simd_group(same_length) == [sm3_hash_scalar(message) for message in same_length]
    assert sm3_hash_many_simd(messages, lanes=4) == [sm3_hash_scalar(message) for message in messages]


def benchmark() -> None:
    messages = [b"SM3 SIMD benchmark message %04d " % index + b"A" * 224 for index in range(64)]

    start = perf_counter()
    scalar_digests = [sm3_hash_scalar(message) for message in messages]
    scalar_elapsed = perf_counter() - start

    print("SM3 multi-buffer benchmark, 64 equal-length messages")
    print(f"  scalar general-register path : {scalar_elapsed:.4f}s")

    for arch, lanes in ARCHITECTURE_LANES.items():
        start = perf_counter()
        simd_digests = sm3_hash_many_simd(messages, lanes)
        elapsed = perf_counter() - start
        assert simd_digests == scalar_digests
        print(f"  {arch:17s} lanes={lanes:2d}: {elapsed:.4f}s, correct=True")

    print(f"  digest[0] = {scalar_digests[0].hex()}")


def print_mapping() -> None:
    print("Hybrid register mapping")
    print("  general registers : loop counter, Tj selection, padding length, block address")
    print("  SIMD registers    : A..H state vectors, W/W' message schedule vectors")
    print("  arm64 target      : NEON EOR/AND/ORR/BIC/ADD/SHL/SRI or SM3 extensions when available")
    print("  x86 AVX2 target   : VPXOR/VPAND/VPOR/VPADDD/VPSLLD/VPSRLD across 8 lanes")
    print("  x86 AVX512 target : same data flow across 16 lanes with zmm registers")


def main() -> None:
    check_vectors()
    print("SM3 official abc test vector: ok")
    print_mapping()
    benchmark()


if __name__ == "__main__":
    main()
