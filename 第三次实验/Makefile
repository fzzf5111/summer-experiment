# SM4 Optimized Implementation Makefile
# Supports x86-64 (T-table, SSSE3, AVX2, PCLMUL) and ARM64 (NEON, SM4E)

AARCH64_CC ?= aarch64-linux-gnu-gcc
CC       ?= gcc
CFLAGS   = -O3 -std=c11 -Wall -Wextra
LDFLAGS  =

# x86-64 builds
x86_sse_TABLE   = -msse2 -mssse3
x86_avx2_FLAGS  = -msse2 -mssse3 -mavx2 -mpclmul -maes
x86_avx512_FLAGS = -mavx512f -mavx512vl -mavx512bw

# ARM64 builds
ARM_NEON_FLAGS  = -march=armv8-a+simd
ARM_SM4E_FLAGS  = -march=armv8.2-a+sm4+simd

.PHONY: all clean test

all: sm4_x86_optimized

sm4_x86_optimized: c_optimized/sm4_x86_optimized.c
	$(CC) $(CFLAGS) $(x86_avx2_FLAGS) $< -o $@ $(LDFLAGS)

sm4_arm_optimized: c_optimized/sm4_arm_optimized.c
	$(AARCH64_CC) $(CFLAGS) $(ARM_NEON_FLAGS) $< -o $@ $(LDFLAGS)

test: sm4_x86_optimized
	./sm4_x86_optimized

clean:
	rm -f sm4_x86_optimized sm4_arm_optimized *.o
