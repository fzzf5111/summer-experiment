# 第四次实验：SM3 软件实现与 SIMD 优化

## 题目

实现 SM3 密码杂凑算法，并基于 SIMD 寄存器和通用寄存器的混合使用方式，分析 ARM64、x86 AVX2、x86 AVX512 上的多消息并行优化思路。

## 结论摘要

SM3 的优化难点和 SM4 不同。SM4 的多个分组可以比较自然地并行，而 SM3 单条消息的 64 轮压缩函数有明显的轮间依赖：

```text
A[j+1] depends on A[j], B[j], C[j], D[j], E[j], W[j], W'[j]
E[j+1] depends on E[j], F[j], G[j], H[j], A[j], W[j]
```

因此，单条消息内部不适合简单拆成多条 SIMD lane 并行计算。本实验采用的是 multi-buffer 思路：同时处理多条独立消息，让每条消息占一个 SIMD lane。这样每个 lane 内仍然按照 SM3 的顺序执行 64 轮，但不同 lane 之间可以并行。

实验实现包含：

1. 标量 SM3：实现 padding、消息扩展、压缩函数和 256 bit 摘要输出。
2. Python SIMD 模型：用 `list[int]` 模拟 4/8/16 lane 的 SIMD 数据流。
3. x86 C intrinsic：实现 AVX2 8-lane 和 AVX512 16-lane multi-buffer 结构。
4. ARM64 C intrinsic：实现 NEON 4-lane multi-buffer 结构，并说明 SM3 crypto extension 的替换位置。
5. Windows VSCode 兼容：默认不启用 AVX2/AVX512 时可以先编译运行标量 fallback。

## SM3 算法背景

SM3 是 Merkle-Damgard 结构的密码杂凑算法。输入消息先 padding 到 512 bit 分组：

```text
message || 1 || zero padding || 64-bit length
```

每个 512 bit 分组进入压缩函数。初始 IV 为 8 个 32 bit 字：

```text
V0 = A || B || C || D || E || F || G || H
```

压缩函数先做消息扩展：

```text
W[0..15]  = message block words
W[j]      = P1(W[j-16] ^ W[j-9] ^ (W[j-3] <<< 15)) ^ (W[j-13] <<< 7) ^ W[j-6]
W'[j]     = W[j] ^ W[j+4]
```

其中：

```text
P0(x) = x ^ (x <<< 9) ^ (x <<< 17)
P1(x) = x ^ (x <<< 15) ^ (x <<< 23)
```

随后执行 64 轮压缩。前 16 轮和后 48 轮的布尔函数不同：

```text
FF_j(x,y,z) = x ^ y ^ z                         j = 0..15
FF_j(x,y,z) = (x & y) | (x & z) | (y & z)       j = 16..63

GG_j(x,y,z) = x ^ y ^ z                         j = 0..15
GG_j(x,y,z) = (x & y) | (~x & z)                j = 16..63
```

每轮的主要更新为：

```text
SS1 = ((A <<< 12) + E + (Tj <<< j)) <<< 7
SS2 = SS1 ^ (A <<< 12)
TT1 = FF(A,B,C) + D + SS2 + W'[j]
TT2 = GG(E,F,G) + H + SS1 + W[j]
E   = P0(TT2)
A   = TT1
```

最后用 Davies-Meyer 结构和输入状态异或：

```text
V_i = compress(V_{i-1}, B_i) ^ V_{i-1}
```

## 代码结构

```text
第四次实验/
├── README.md
├── Makefile
├── sm3_simd_hybrid_demo.py
└── c_optimized/
    ├── sm3_x86_simd.c
    └── sm3_arm_neon.c
```

Python 文件负责表达完整算法和 SIMD lane 模型；C 文件负责把同一数据流映射到真实寄存器和 intrinsic。

## 代码思路：标量正确性基准

所有 SIMD 优化都必须先有一个可信的标量实现作为基准。代码中的标量路径按标准拆成四步：

```text
sm3_padded_len     计算 padding 后长度
sm3_pad            生成 512 bit 对齐消息
sm3_compress_scalar 单分组压缩
sm3_hash_scalar    多分组迭代并输出 digest
```

`sm3_compress_scalar` 中保留 `W[68]` 和 `W1[64]` 两个数组，直接对应标准公式。这样做牺牲了一些空间，但让代码更适合作为验证基准：SIMD 结果只要逐 lane 和标量结果比较，就能证明多消息并行没有改变 SM3 语义。

## 代码思路：为什么采用 multi-buffer

SM3 单条消息的 64 轮压缩存在强依赖。例如第 `j+1` 轮的 `A` 来自第 `j` 轮的 `TT1`，`E` 来自第 `j` 轮的 `P0(TT2)`。这意味着单条消息不能像数组求和那样把 64 轮拆开并行。

可行的 SIMD 方法是把“多条消息”并行：

```text
lane 0: message_0 的 A/B/C/D/E/F/G/H
lane 1: message_1 的 A/B/C/D/E/F/G/H
...
lane n: message_n 的 A/B/C/D/E/F/G/H
```

于是一个 SIMD 寄存器不保存同一消息的多个状态字，而是保存多条消息的同一个状态字：

```text
A_vec = [A0, A1, A2, ..., A_lanes-1]
B_vec = [B0, B1, B2, ..., B_lanes-1]
...
H_vec = [H0, H1, H2, ..., H_lanes-1]
```

每轮仍然按顺序执行，但一条 SIMD 指令同时处理多个 lane：

```text
TT1_vec = FF(A_vec,B_vec,C_vec) + D_vec + SS2_vec + W1_vec[j]
TT2_vec = GG(E_vec,F_vec,G_vec) + H_vec + SS1_vec + W_vec[j]
```

这就是 README 中“SIMD 寄存器和通用寄存器混合”的含义。

## 代码思路：寄存器分工

通用寄存器负责控制逻辑：

```text
j                 轮计数
Tj                常量选择
msg pointer       每条消息的分组地址
padlen/nblocks    padding 后长度和分组循环
lane index        装载/回写每个 lane 的摘要
```

SIMD 寄存器负责数据通路：

```text
A..H              8 个状态向量
W[0..67]          消息扩展向量
W'[0..63]         辅助消息向量
SS1/SS2/TT1/TT2   每轮临时向量
```

这种分工的好处是：分支、地址计算、循环控制仍然由普通整数寄存器完成；32 bit 加法、异或、与、或、移位等重复数据计算交给 SIMD。

## 代码思路：x86 AVX2 与 AVX512

AVX2 使用 256 bit YMM 寄存器。SM3 的基本字宽是 32 bit，因此一个 YMM 寄存器可以放 8 个 lane：

```text
256 / 32 = 8
```

代码中 `sm3_compress_avx2` 的结构和标量压缩函数基本一致，只是把 `uint32_t` 换成 `__m256i`：

```text
XOR       -> _mm256_xor_si256
AND       -> _mm256_and_si256
OR        -> _mm256_or_si256
ADD       -> _mm256_add_epi32
ROTL32    -> slli + srli + or
```

消息装载时先把每条消息的第 `j` 个 32 bit 字取出来，组成一个 8-lane 向量：

```text
w[j] = [W0[j], W1[j], W2[j], W3[j], W4[j], W5[j], W6[j], W7[j]]
```

AVX512 使用 512 bit ZMM 寄存器，可以放 16 个 32 bit lane：

```text
512 / 32 = 16
```

AVX512 的优势不只是 lane 数翻倍，还包括更强的位运算指令。例如三输入布尔函数可以用 `VPTERNLOGD` 表示：

```text
FF xor       -> ternary logic immediate 0x96
FF majority  -> ternary logic immediate 0xE8
GG choose    -> ternary logic immediate 0xD8
```

如果目标 CPU 支持对应 rotate 指令，循环左移也可以从“两个移位加一个或”缩短为单条 rotate。

## 代码思路：ARM64 NEON 与 SM3 扩展

ARM64 NEON 是 128 bit 宽，因此自然对应 4 个 32 bit lane：

```text
128 / 32 = 4
```

代码中 NEON 路径使用：

```text
EOR       -> veorq_u32
AND       -> vandq_u32
ORR       -> vorrq_u32
BIC       -> vbicq_u32
ADD       -> vaddq_u32
ROTL32    -> vshlq + vshrq + vorrq
```

`GG` 后 48 轮的：

```text
(x & y) | (~x & z)
```

在 NEON 中可以写成：

```text
vorrq_u32(vandq_u32(x, y), vbicq_u32(z, x))
```

因为 `vbicq_u32(z, x)` 表示 `z & ~x`。

ARMv8.2-A 以后还定义了 SM3 专用指令，例如 `SM3SS1`、`SM3TT1A/B`、`SM3TT2A/B`、`SM3PARTW1/2`。这些指令可以把软件中的布尔函数、SS1 计算和消息扩展替换成硬件指令。实验代码把这部分作为可选硬件路径说明，因为不同编译器和机器对 SM3 crypto extension 的支持不完全一致。

## 代码运行结果

Python 主程序输出如下：

```text
SM3 official abc test vector: ok
Hybrid register mapping
  general registers : loop counter, Tj selection, padding length, block address
  SIMD registers    : A..H state vectors, W/W' message schedule vectors
  arm64 target      : NEON EOR/AND/ORR/BIC/ADD/SHL/SRI or SM3 extensions when available
  x86 AVX2 target   : VPXOR/VPAND/VPOR/VPADDD/VPSLLD/VPSRLD across 8 lanes
  x86 AVX512 target : same data flow across 16 lanes with zmm registers
SM3 multi-buffer benchmark, 64 equal-length messages
  scalar general-register path : 0.0849s
  arm64-neon-128    lanes= 4: 0.0917s, correct=True
  x86-avx2-256      lanes= 8: 0.0884s, correct=True
  x86-avx512-512    lanes=16: 0.0774s, correct=True
  digest[0] = ed003a8dd3a5ce86ab411121de253bfc859b0191f5f17bff283bb9bacdffa261
```

x86 AVX2 C 版本输出如下：

```text
=== SM3 SIMD Multi-Buffer Implementation ===

Architecture: x86 AVX2 (8 lanes × 32-bit YMM)
Register strategy:
  General registers: loop counter, Tj, block address, padding
  SIMD registers:    A..H state, W[68] schedule, W'[64]

SM3("abc") test: PASS
AVX2 8-lane multi-buffer test: PASS

SM3 performance benchmark (10000 hashes of 64-byte message):
  Scalar: 0.0085 s,  71.78 MiB/s processed

SIMD optimization paths (when compiled with flags):
  AVX2  (8 lanes):  VPXOR/VPAND/VPOR/VPADDD/VPSLLD/VPSRLD
  AVX512 (16 lanes): requires /arch:AVX512 or -mavx512f
  Hybrid: general registers for control + SIMD for state
```

普通 C11 fallback 输出如下，用于说明没有开启 AVX2/AVX512 时也可以跑通基础验证：

```text
=== SM3 SIMD Multi-Buffer Implementation ===

Architecture: x86-64 (scalar fallback)
Register strategy:
  General registers: loop counter, Tj, block address, padding
  SIMD registers:    A..H state, W[68] schedule, W'[64]

SM3("abc") test: PASS

SM3 performance benchmark (10000 hashes of 64-byte message):
  Scalar: 0.0078 s,  78.75 MiB/s processed

SIMD optimization paths (when compiled with flags):
  AVX2  (8 lanes):  requires /arch:AVX2 or -mavx2
  AVX512 (16 lanes): requires /arch:AVX512 or -mavx512f
  Hybrid: general registers for control + SIMD for state
```

ARM 文件在当前 x86 机器上走 fallback，输出如下：

```text
=== SM3 ARM64 NEON Multi-Buffer Implementation ===

Architecture: generic (scalar only)
Register strategy:
  General registers: loop counter, Tj, block pointer, padding
  NEON Q-registers:  A..H state vectors (8×Q), W schedule (on-the-fly)

SM3("abc") test: PASS

SM3 scalar benchmark (10000 hashes of 64-byte message):
  Scalar: 0.0078 s,  78.12 MiB/s
```

AVX512 版本已经完成编译检查；当前机器不支持 AVX512 运行，所以不把它作为本机运行结果。

## 实验结论

本次实验可以总结为：

1. SM3 的单消息压缩函数有强轮间依赖，优化重点应放在多消息并行，而不是强行拆分单条消息内部的 64 轮。
2. multi-buffer 方法把多条消息映射到 SIMD lane，使 `A..H`、`W`、`W'` 都变成向量，保持 SM3 语义不变。
3. AVX2 对应 8 lane，AVX512 对应 16 lane，ARM64 NEON 对应 4 lane；lane 数由 SIMD 寄存器宽度和 SM3 的 32 bit 字宽共同决定。
4. AVX512 的 `VPTERNLOGD`、ARM64 的 SM3 crypto extension 可以进一步减少布尔函数和消息扩展的指令数。
5. C 文件现在支持 Windows VSCode 的默认标量 fallback；真正启用 AVX2/AVX512/NEON 时，再由编译器和目标 CPU 决定是否进入 SIMD 路径。

## 参考资料

- GB/T 32905-2016：信息安全技术 SM3 密码杂凑算法
- GM/T 0004-2012：SM3 密码杂凑算法
- Arm Architecture Reference Manual：NEON、SM3 crypto extension
- Intel Intrinsics Guide：AVX2、AVX512、VPTERNLOGD、VPROLD
- RFC 8998：Use of the SM2 Signature Algorithm and SM3 Hash Algorithm in TLS 1.3
