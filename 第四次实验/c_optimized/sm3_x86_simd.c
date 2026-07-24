/**
 * SM3 x86 SIMD multi-buffer implementation
 *
 * Implements SIMD + general-register hybrid optimization:
 *   - General registers: loop counter, Tj selection, block address, padding length
 *   - SIMD registers: A..H state vectors (8×32-bit or 16×32-bit lanes)
 *
 * Supports two x86 architectures:
 *   1. AVX2  (256-bit YMM, 8 lanes)
 *   2. AVX512 (512-bit ZMM, 16 lanes)
 *
 * Build (GCC/Clang):
 *   gcc -O3 -mavx2 -std=c11 sm3_x86_simd.c -o sm3_x86_simd_avx2
 *   gcc -O3 -mavx512f -mavx512vl -std=c11 sm3_x86_simd.c -o sm3_x86_simd_avx512
 *
 * Build (MSVC):
 *   cl /O2 /arch:AVX2 sm3_x86_simd.c
 *   cl /O2 /arch:AVX512 sm3_x86_simd.c
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __x86_64__
#include <immintrin.h>  /* AVX, AVX2, AVX512 */
#endif

/* ---------------------------------------------------------------------------
 * SM3 Constants
 * --------------------------------------------------------------------------- */

#define SM3_BLOCK_SIZE  64
#define SM3_DIGEST_SIZE 32

static const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

static const uint32_t T[2] = { 0x79CC4519, 0x7A879D8A };

/* ===========================================================================
 * Scalar reference implementation (general register path)
 * =========================================================================== */

static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

static uint32_t sm3_p0(uint32_t x) {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

static uint32_t sm3_p1(uint32_t x) {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

static uint32_t sm3_ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static uint32_t sm3_gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

static void sm3_pad(const uint8_t *msg, size_t msglen,
                    uint8_t *padded, size_t *padlen) {
    *padlen = msglen + 1;
    while ((*padlen % SM3_BLOCK_SIZE) != 56) (*padlen)++;
    *padlen += 8;

    memcpy(padded, msg, msglen);
    padded[msglen] = 0x80;
    memset(padded + msglen + 1, 0, *padlen - msglen - 1 - 8);

    uint64_t bits = (uint64_t)msglen * 8;
    for (int i = 0; i < 8; i++)
        padded[*padlen - 8 + i] = (uint8_t)(bits >> (56 - 8 * i));
}

static void sm3_compress_scalar(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[68], w1[64];
    /* Message expansion */
    for (int j = 0; j < 16; j++) {
        w[j] = ((uint32_t)block[4*j]   << 24) | ((uint32_t)block[4*j+1] << 16) |
               ((uint32_t)block[4*j+2] <<  8) | ((uint32_t)block[4*j+3]);
    }
    for (int j = 16; j < 68; j++) {
        w[j] = sm3_p1(w[j-16] ^ w[j-9] ^ rotl32(w[j-3], 15)) ^
               rotl32(w[j-13], 7) ^ w[j-6];
    }
    for (int j = 0; j < 64; j++)
        w1[j] = w[j] ^ w[j+4];

    uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
    uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

    for (int j = 0; j < 64; j++) {
        uint32_t tj  = (j < 16) ? T[0] : T[1];
        uint32_t ss1 = rotl32(rotl32(A, 12) + E + rotl32(tj, j % 32), 7);
        uint32_t ss2 = ss1 ^ rotl32(A, 12);
        uint32_t tt1 = sm3_ff(A, B, C, j) + D + ss2 + w1[j];
        uint32_t tt2 = sm3_gg(E, F, G, j) + H + ss1 + w[j];
        D = C;
        C = rotl32(B, 9);
        B = A;
        A = tt1;
        H = G;
        G = rotl32(F, 19);
        F = E;
        E = sm3_p0(tt2);
    }

    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

void sm3_hash_scalar(const uint8_t *msg, size_t msglen, uint8_t digest[32]) {
    uint8_t padded[SM3_BLOCK_SIZE * 32]; /* enough for short messages */
    size_t padlen;
    sm3_pad(msg, msglen, padded, &padlen);

    uint32_t state[8];
    memcpy(state, IV, sizeof(IV));

    for (size_t off = 0; off < padlen; off += SM3_BLOCK_SIZE)
        sm3_compress_scalar(state, padded + off);

    for (int i = 0; i < 8; i++) {
        digest[4*i]   = (uint8_t)(state[i] >> 24);
        digest[4*i+1] = (uint8_t)(state[i] >> 16);
        digest[4*i+2] = (uint8_t)(state[i] >> 8);
        digest[4*i+3] = (uint8_t)(state[i]);
    }
}

/* ===========================================================================
 * AVX2 multi-buffer SM3 (8 lanes, 256-bit YMM registers)
 *
 * Processes 8 independent messages in parallel. Each 32-bit lane in
 * the YMM register holds the same state word for a different message.
 *
 * General registers handle:
 *   - Round index j
 *   - Tj constant selection
 *   - Block address pointers
 *   - Padding length / loop control
 *
 * SIMD (YMM) registers hold:
 *   - A..H: 8 state word vectors
 *   - W[68], W1[64]: message schedule vectors
 * =========================================================================== */

#ifdef __x86_64__

/* Broadcast a 32-bit scalar to all 8 lanes of a YMM register */
static inline __m256i ymm_set1_epi32(uint32_t v) {
    return _mm256_set1_epi32((int)v);
}

/* 32-bit rotate-left across all 8 lanes */
static inline __m256i ymm_rotl32(__m256i v, int n) {
    __m256i left  = _mm256_slli_epi32(v, n);
    __m256i right = _mm256_srli_epi32(v, 32 - n);
    return _mm256_or_si256(left, right);
}

/* P0 function across all lanes */
static inline __m256i ymm_p0(__m256i x) {
    return _mm256_xor_si256(
        _mm256_xor_si256(x, ymm_rotl32(x, 9)),
        ymm_rotl32(x, 17));
}

/* P1 function across all lanes */
static inline __m256i ymm_p1(__m256i x) {
    return _mm256_xor_si256(
        _mm256_xor_si256(x, ymm_rotl32(x, 15)),
        ymm_rotl32(x, 23));
}

/* FF function: j<16 → XOR; j>=16 → majority */
static inline __m256i ymm_ff(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16)
        return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    /* (x & y) | (x & z) | (y & z) */
    __m256i xy = _mm256_and_si256(x, y);
    __m256i xz = _mm256_and_si256(x, z);
    __m256i yz = _mm256_and_si256(y, z);
    return _mm256_or_si256(_mm256_or_si256(xy, xz), yz);
}

/* GG function: j<16 → XOR; j>=16 → (x&y) | (~x&z) */
static inline __m256i ymm_gg(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16)
        return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    __m256i not_x = _mm256_andnot_si256(x, _mm256_set1_epi32(-1));
    return _mm256_or_si256(
        _mm256_and_si256(x, y),
        _mm256_and_si256(not_x, z));
}

/**
 * AVX2 SM3 compress: process 8 messages × 64 bytes in parallel.
 *
 * block_words_by_lane[8][16] contains 16 initial W-words for each message.
 */
static void sm3_compress_avx2(__m256i state[8],
                              const uint32_t block_words[8][16]) {
    /* Load initial W[0..15] from all 8 lanes */
    __m256i w[68], w1[64];
    for (int j = 0; j < 16; j++) {
        uint32_t vals[8];
        for (int lane = 0; lane < 8; lane++)
            vals[lane] = block_words[lane][j];
        w[j] = _mm256_loadu_si256((__m256i*)vals);
    }

    /* Message expansion (W[16..67]) */
    for (int j = 16; j < 68; j++) {
        __m256i t = _mm256_xor_si256(
            _mm256_xor_si256(w[j-16], w[j-9]),
            ymm_rotl32(w[j-3], 15));
        t = ymm_p1(t);
        t = _mm256_xor_si256(t, ymm_rotl32(w[j-13], 7));
        t = _mm256_xor_si256(t, w[j-6]);
        w[j] = t;
    }
    /* W'[0..63] = W[j] ^ W[j+4] */
    for (int j = 0; j < 64; j++)
        w1[j] = _mm256_xor_si256(w[j], w[j+4]);

    /* Load state */
    __m256i A = state[0], B = state[1], C = state[2], D = state[3];
    __m256i E = state[4], F = state[5], G = state[6], H = state[7];

    /* Compression: 64 rounds */
    for (int j = 0; j < 64; j++) {
        uint32_t tj = (j < 16) ? T[0] : T[1];
        __m256i tj_vec   = ymm_set1_epi32(tj);
        __m256i tj_rot   = ymm_set1_epi32(rotl32(tj, j % 32));
        __m256i a12      = ymm_rotl32(A, 12);

        __m256i ss1 = ymm_rotl32(
            _mm256_add_epi32(_mm256_add_epi32(a12, E), tj_rot), 7);
        __m256i ss2 = _mm256_xor_si256(ss1, a12);

        __m256i ff_val = ymm_ff(A, B, C, j);
        __m256i gg_val = ymm_gg(E, F, G, j);

        __m256i tt1 = _mm256_add_epi32(
            _mm256_add_epi32(_mm256_add_epi32(ff_val, D), ss2), w1[j]);
        __m256i tt2 = _mm256_add_epi32(
            _mm256_add_epi32(_mm256_add_epi32(gg_val, H), ss1), w[j]);

        D = C;
        C = ymm_rotl32(B, 9);
        B = A;
        A = tt1;
        H = G;
        G = ymm_rotl32(F, 19);
        F = E;
        E = ymm_p0(tt2);
    }

    /* Davies-Meyer feed-forward */
    state[0] = _mm256_xor_si256(state[0], A);
    state[1] = _mm256_xor_si256(state[1], B);
    state[2] = _mm256_xor_si256(state[2], C);
    state[3] = _mm256_xor_si256(state[3], D);
    state[4] = _mm256_xor_si256(state[4], E);
    state[5] = _mm256_xor_si256(state[5], F);
    state[6] = _mm256_xor_si256(state[6], G);
    state[7] = _mm256_xor_si256(state[7], H);
}

/**
 * Hash up to 8 equal-length messages using AVX2 multi-buffer.
 */
void sm3_hash_avx2_8x(const uint8_t *msgs[8], size_t msglen,
                      uint8_t digests[8][32]) {
    /* Pad all messages identically (equal length => same pad length) */
    uint8_t padded[8][SM3_BLOCK_SIZE * 32];
    size_t padlen;
    sm3_pad(msgs[0], msglen, padded[0], &padlen);

    for (int lane = 0; lane < 8; lane++)
        sm3_pad(msgs[lane], msglen, padded[lane], &padlen);

    /* Initialize state for all 8 lanes */
    __m256i state[8];
    for (int i = 0; i < 8; i++)
        state[i] = ymm_set1_epi32(IV[i]);

    /* Process each block group */
    size_t nblocks = padlen / SM3_BLOCK_SIZE;
    for (size_t b = 0; b < nblocks; b++) {
        uint32_t block_words[8][16];
        for (int lane = 0; lane < 8; lane++) {
            const uint8_t *block = padded[lane] + b * SM3_BLOCK_SIZE;
            for (int j = 0; j < 16; j++) {
                block_words[lane][j] =
                    ((uint32_t)block[4*j]   << 24) |
                    ((uint32_t)block[4*j+1] << 16) |
                    ((uint32_t)block[4*j+2] <<  8) |
                    ((uint32_t)block[4*j+3]);
            }
        }
        sm3_compress_avx2(state, block_words);
    }

    /* Extract digests from lane 0 */
    for (int lane = 0; lane < 8; lane++) {
        for (int i = 0; i < 8; i++) {
            uint32_t val;
            _mm256_maskstore_epi32((int*)&val, _mm256_set1_epi32(1), state[i]);
            /* Simplified: in production, use pextract or store+lane indexing */
            /* For now, store to aligned buffer and extract */
        }
        /* Extract: use a proper method to read per-lane values */
        uint32_t state_buf[8 * 8] __attribute__((aligned(32)));
        for (int i = 0; i < 8; i++)
            _mm256_store_si256((__m256i*)(state_buf + i*8), state[i]);

        for (int i = 0; i < 8; i++) {
            uint32_t v = state_buf[i * 8 + lane];
            digests[lane][4*i]   = (uint8_t)(v >> 24);
            digests[lane][4*i+1] = (uint8_t)(v >> 16);
            digests[lane][4*i+2] = (uint8_t)(v >> 8);
            digests[lane][4*i+3] = (uint8_t)(v);
        }
    }
}

/* ===========================================================================
 * AVX512 multi-buffer SM3 (16 lanes, 512-bit ZMM registers)
 *
 * Same logic as AVX2 but with twice the lane count.
 * AVX512 advantages:
 *   - VPTERNLOGD for 3-input boolean functions (FF/GG in 1 instruction)
 *   - VPROLD for single-instruction rotate-left (if available)
 *   - Mask registers for partial groups
 * =========================================================================== */

#ifdef __AVX512F__

static inline __m512i zmm_set1_epi32(uint32_t v) {
    return _mm512_set1_epi32((int)v);
}

static inline __m512i zmm_rotl32(__m512i v, int n) {
#ifdef __AVX512VL__
    /* VPROLD is available on some AVX512 implementations */
    return _mm512_rol_epi32(v, n);
#else
    __m512i left  = _mm512_slli_epi32(v, n);
    __m512i right = _mm512_srli_epi32(v, 32 - n);
    return _mm512_or_si512(left, right);
#endif
}

static inline __m512i zmm_p0(__m512i x) {
    return _mm512_xor_si512(
        _mm512_xor_si512(x, zmm_rotl32(x, 9)),
        zmm_rotl32(x, 17));
}

static inline __m512i zmm_p1(__m512i x) {
    return _mm512_xor_si512(
        _mm512_xor_si512(x, zmm_rotl32(x, 15)),
        zmm_rotl32(x, 23));
}

/* AVX512 VPTERNLOGD: single-instruction 3-input LUT-based boolean function
 *
 * For FF (j<16):  XOR → VPTERNLOGD with 0x96
 * For FF (j>=16): majority → VPTERNLOGD with 0xE8
 * For GG (j<16):  XOR → VPTERNLOGD with 0x96
 * For GG (j>=16): (x&y) | (~x&z) → VPTERNLOGD with 0xD8
 */
static inline __m512i zmm_ff(__m512i x, __m512i y, __m512i z, int j) {
    if (j < 16)
        return _mm512_ternarylogic_epi32(x, y, z, 0x96); /* A^B^C */
    return _mm512_ternarylogic_epi32(x, y, z, 0xE8);     /* (A&B)|(A&C)|(B&C) */
}

static inline __m512i zmm_gg(__m512i x, __m512i y, __m512i z, int j) {
    if (j < 16)
        return _mm512_ternarylogic_epi32(x, y, z, 0x96); /* A^B^C */
    return _mm512_ternarylogic_epi32(x, y, z, 0xD8);     /* (A&B)|(~A&C) */
}

/**
 * AVX512 SM3 compress: 16 messages in parallel.
 */
static void sm3_compress_avx512(__m512i state[8],
                                const uint32_t block_words[16][16]) {
    __m512i w[68], w1[64];

    for (int j = 0; j < 16; j++) {
        uint32_t vals[16];
        for (int lane = 0; lane < 16; lane++)
            vals[lane] = block_words[lane][j];
        w[j] = _mm512_loadu_si512(vals);
    }

    for (int j = 16; j < 68; j++) {
        __m512i t = _mm512_xor_si512(
            _mm512_xor_si512(w[j-16], w[j-9]),
            zmm_rotl32(w[j-3], 15));
        t = zmm_p1(t);
        t = _mm512_xor_si512(t, zmm_rotl32(w[j-13], 7));
        t = _mm512_xor_si512(t, w[j-6]);
        w[j] = t;
    }
    for (int j = 0; j < 64; j++)
        w1[j] = _mm512_xor_si512(w[j], w[j+4]);

    __m512i A = state[0], B = state[1], C = state[2], D = state[3];
    __m512i E = state[4], F = state[5], G = state[6], H = state[7];

    for (int j = 0; j < 64; j++) {
        uint32_t tj = (j < 16) ? T[0] : T[1];
        __m512i tj_vec  = zmm_set1_epi32(tj);
        __m512i tj_rot  = zmm_set1_epi32(rotl32(tj, j % 32));
        __m512i a12     = zmm_rotl32(A, 12);

        __m512i ss1 = zmm_rotl32(
            _mm512_add_epi32(_mm512_add_epi32(a12, E), tj_rot), 7);
        __m512i ss2 = _mm512_xor_si512(ss1, a12);

        __m512i ff_val = zmm_ff(A, B, C, j);
        __m512i gg_val = zmm_gg(E, F, G, j);

        __m512i tt1 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(ff_val, D), ss2), w1[j]);
        __m512i tt2 = _mm512_add_epi32(
            _mm512_add_epi32(_mm512_add_epi32(gg_val, H), ss1), w[j]);

        D = C; C = zmm_rotl32(B, 9); B = A; A = tt1;
        H = G; G = zmm_rotl32(F, 19); F = E; E = zmm_p0(tt2);
    }

    state[0] = _mm512_xor_si512(state[0], A);
    state[1] = _mm512_xor_si512(state[1], B);
    state[2] = _mm512_xor_si512(state[2], C);
    state[3] = _mm512_xor_si512(state[3], D);
    state[4] = _mm512_xor_si512(state[4], E);
    state[5] = _mm512_xor_si512(state[5], F);
    state[6] = _mm512_xor_si512(state[6], G);
    state[7] = _mm512_xor_si512(state[7], H);
}

#endif /* __AVX512F__ */

#endif /* __x86_64__ */

/* ===========================================================================
 * Self-test and benchmark
 * =========================================================================== */

#include <time.h>

static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void) {
    printf("=== SM3 SIMD Multi-Buffer Implementation ===\n\n");

    /* Architecture info */
#if defined(__AVX512F__)
    printf("Architecture: x86 AVX-512 (16 lanes × 32-bit ZMM)\n");
#elif defined(__AVX2__)
    printf("Architecture: x86 AVX2 (8 lanes × 32-bit YMM)\n");
#elif defined(__x86_64__)
    printf("Architecture: x86-64 (scalar fallback)\n");
#elif defined(__aarch64__)
    printf("Architecture: ARM64 (see sm3_arm_neon.c for NEON path)\n");
#else
    printf("Architecture: generic (scalar only)\n");
#endif

    printf("Register strategy:\n");
    printf("  General registers: loop counter, Tj, block address, padding\n");
    printf("  SIMD registers:    A..H state, W[68] schedule, W'[64]\n\n");

    /* Test vector: SM3("abc") */
    const uint8_t *msg = (const uint8_t*)"abc";
    uint8_t expected[32] = {
        0x66,0xC7,0xF0,0xF4,0x62,0xEE,0xED,0xD9,
        0xD1,0xF2,0xD4,0x6B,0xDC,0x10,0xE4,0xE2,
        0x41,0x67,0xC4,0x87,0x5C,0xF2,0xF7,0xA2,
        0x29,0x7D,0xA0,0x2B,0x8F,0x4B,0xA8,0xE0
    };

    uint8_t digest[32];
    sm3_hash_scalar(msg, 3, digest);
    printf("SM3(\"abc\") test: %s\n",
           memcmp(digest, expected, 32) == 0 ? "PASS" : "FAIL");

    /* Benchmark scalar */
    printf("\nSM3 performance benchmark (10000 hashes of 64-byte message):\n");
    const int N = 10000;
    uint8_t bench_msg[64];
    memset(bench_msg, 0xAB, 64);

    double start = get_time_sec();
    for (int i = 0; i < N; i++) {
        bench_msg[0] = (uint8_t)i;
        sm3_hash_scalar(bench_msg, 64, digest);
    }
    double elapsed = get_time_sec() - start;
    double mib = (double)(N * 64) / (1024.0 * 1024.0);
    printf("  Scalar: %.4f s,  %.2f MiB/s processed\n", elapsed, mib / elapsed);

#ifdef __x86_64__
    printf("\nSIMD optimization paths (when compiled with flags):\n");
    printf("  AVX2  (8 lanes):  VPXOR/VPAND/VPOR/VPADDD/VPSLLD/VPSRLD\n");
    printf("  AVX512 (16 lanes): VPTERNLOGD (3-in boolean) + VPROLD (rotate)\n");
    printf("  Hybrid: general registers for control + SIMD for state\n");
#endif

    return 0;
}
