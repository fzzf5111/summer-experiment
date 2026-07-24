# SM3 SIMD Multi-Buffer Implementation Makefile
# Supports x86-64 (scalar, AVX2, AVX512) and ARM64 (NEON, SM3E)

CC       = gcc
CFLAGS   = -O3 -std=c11 -Wall -Wextra
LDFLAGS  =

# x86-64 builds
x86_SCALAR      = 
x86_AVX2_FLAGS  = -mavx2
x86_AVX512_FLAGS = -mavx512f -mavx512vl

# ARM64 builds
ARM_NEON_FLAGS  = -march=armv8-a+simd
ARM_SM3E_FLAGS  = -march=armv8.2-a+sm3+simd

.PHONY: all clean test

all: sm3_x86_simd

sm3_x86_simd: c_optimized/sm3_x86_simd.c
	$(CC) $(CFLAGS) $(x86_AVX2_FLAGS) $< -o $@ $(LDFLAGS)

sm3_x86_avx512: c_optimized/sm3_x86_simd.c
	$(CC) $(CFLAGS) $(x86_AVX512_FLAGS) $< -o $@ $(LDFLAGS)

sm3_arm_neon: c_optimized/sm3_arm_neon.c
	$(CC) $(CFLAGS) $(ARM_NEON_FLAGS) $< -o $@ $(LDFLAGS)

test: sm3_x86_simd
	./sm3_x86_simd

clean:
	rm -f sm3_x86_simd sm3_x86_avx512 sm3_arm_neon *.o
