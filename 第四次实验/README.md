# 暑期实验课实验：第四次实验

## 题目

SM3 软件实现与优化：

实现基于 SIMD 寄存器和通用寄存器混合的 SM3 算法优化实现，要求实现 ARM64 和 x86（AVX2/AVX512）中的两种架构指令集。

## 结论摘要

本次实验实现了 SM3 的完整软件哈希流程，包括消息填充、消息扩展、压缩函数和最终摘要输出。

代码中包含两类实现：

1. 标量实现：所有 32-bit 状态字都用普通整数计算，作为正确性基准。
2. SIMD-hybrid 模型：用 Python 的 `list[int]` 表示 SIMD 寄存器中的多个 32-bit lane，一次并行处理多条等长消息；循环计数、常量选择、消息长度和分组地址仍由通用寄存器逻辑控制。

实验覆盖三种指令集映射：

1. ARM64 NEON：128-bit SIMD，一次处理 4 个 32-bit lane。
2. x86 AVX2：256-bit SIMD，一次处理 8 个 32-bit lane。
3. x86 AVX512：512-bit SIMD，一次处理 16 个 32-bit lane。

Python 代码本身不会发出 NEON/AVX 指令，因此它是一个可运行、可验证的数据流模型。真正的性能优化需要在 C/C++ intrinsic 或汇编中把模型中的向量操作替换成 `EOR/AND/ORR/ADD/SHL`、`VPXOR/VPAND/VPOR/VPADDD/VPSLLD`、`VPTERNLOGD/VPROLD` 等机器指令。

## 背景：SM3 哈希算法

SM3 是国家商用密码杂凑算法，输出长度为 256 bit，分组长度为 512 bit。整体结构和 SHA-256 类似，使用 Merkle-Damgard 迭代压缩结构：

```text
V0 = IV
Vi+1 = CF(Vi, Bi)
digest = Vn
```

初始向量为 8 个 32-bit 字：

```text
7380166f 4914b2b9 172442d7 da8a0600
a96f30bc 163138aa e38dee4d b0fb0e4e
```

每个 512-bit 消息分组先被拆成 16 个 32-bit 大端字：

```text
W0, W1, ..., W15
```

然后扩展到 68 个字：

```text
Wj = P1(Wj-16 xor Wj-9 xor (Wj-3 <<< 15)) xor (Wj-13 <<< 7) xor Wj-6
```

再生成 64 个辅助字：

```text
W'j = Wj xor Wj+4
```

压缩函数中使用 8 个工作变量：

```text
A, B, C, D, E, F, G, H
```

每轮执行布尔函数、模 `2^32` 加法、循环左移和置换函数 `P0`。

## 标量实现

标量实现直接按照 SM3 标准公式编写。核心函数包括：

```python
def p0(value: int) -> int:
    return value ^ rotl32(value, 9) ^ rotl32(value, 17)

def p1(value: int) -> int:
    return value ^ rotl32(value, 15) ^ rotl32(value, 23)
```

布尔函数为：

```python
def ff(x: int, y: int, z: int, round_index: int) -> int:
    if round_index < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

def gg(x: int, y: int, z: int, round_index: int) -> int:
    if round_index < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & MASK32) & z)
```

压缩函数每轮计算：

```text
SS1 = ((A <<< 12) + E + (Tj <<< j)) <<< 7
SS2 = SS1 xor (A <<< 12)
TT1 = FFj(A,B,C) + D + SS2 + W'j
TT2 = GGj(E,F,G) + H + SS1 + Wj
```

最后将工作变量与输入状态异或：

```text
Vi+1 = A..H xor Vi
```

代码使用 SM3 标准测试向量验证：

```text
SM3("abc")
= 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

## SIMD 与通用寄存器混合设计

SM3 的单条消息压缩函数轮间依赖很强：

```text
round j+1 depends on A..H after round j
```

因此单条短消息很难像 CTR 模式那样简单地拆成很多完全独立的块并行。更实际的软件优化方法是 multi-buffer SIMD：同时处理多条独立消息，让每条消息占用 SIMD 寄存器中的一个 lane。

例如 4 lane 模型中：

```text
A = [A_msg0, A_msg1, A_msg2, A_msg3]
B = [B_msg0, B_msg1, B_msg2, B_msg3]
...
H = [H_msg0, H_msg1, H_msg2, H_msg3]
```

每一轮对所有 lane 执行同一条向量指令：

```text
VPADDD A, B, C
VPXOR  X, Y, Z
VPSLLD/VPSRLD/VPOR implement rotate-left
```

通用寄存器负责控制：

```text
round index j
Tj selection
message block pointer
padding length
loop branch
```

SIMD 寄存器负责保存和更新：

```text
A..H state vectors
W0..W67 message schedule vectors
W'0..W'63 expanded schedule vectors
```

这就是本实验所说的“SIMD 寄存器和通用寄存器混合实现”。

## ARM64 实现路径

ARM64 NEON 是 128-bit SIMD。对于 SM3 的 32-bit word 操作，可以一次容纳 4 个 lane：

```text
uint32x4_t A, B, C, D, E, F, G, H;
```

常用指令映射为：

```text
xor        -> EOR
and        -> AND
or         -> ORR
not-and    -> BIC
add mod 2^32 -> ADD
shift left -> SHL
shift right -> USHR
rotate left -> SHL + USHR + ORR
```

如果目标 ARM64 CPU 支持 SM3 专用扩展，还可以进一步使用：

```text
SM3SS1
SM3TT1A / SM3TT1B
SM3TT2A / SM3TT2B
SM3PARTW1 / SM3PARTW2
```

这些指令把 SM3 压缩函数中的特殊布尔和消息扩展步骤做成硬件辅助操作。实验代码中的 `arm64-neon-128` 对应 4 lane multi-buffer 数据流。

## x86 AVX2 实现路径

x86 AVX2 使用 256-bit YMM 寄存器。SM3 的基本字长是 32 bit，因此一个 YMM 寄存器可以并行保存 8 条消息的同一个状态字：

```text
__m256i A, B, C, D, E, F, G, H;
```

常用 intrinsic 映射为：

```text
xor        -> _mm256_xor_si256
and        -> _mm256_and_si256
or         -> _mm256_or_si256
add        -> _mm256_add_epi32
shift left -> _mm256_slli_epi32
shift right -> _mm256_srli_epi32
rotate left -> shift left + shift right + or
```

SM3 第 16 轮之后的 `FF` 和 `GG` 可以用 `AND/OR/XOR` 组合实现。AVX2 没有通用的 32-bit rotate 指令，因此 rotate 通常需要三条指令组合。

实验代码中的 `x86-avx2-256` 对应 8 lane multi-buffer 数据流。

## x86 AVX512 实现路径

AVX512 使用 512-bit ZMM 寄存器，可以一次容纳 16 个 32-bit lane：

```text
__m512i A, B, C, D, E, F, G, H;
```

相比 AVX2，AVX512 的优势有：

1. lane 数量从 8 增加到 16。
2. 可以使用更丰富的逻辑指令，例如 `VPTERNLOGD` 表示三输入布尔函数。
3. 在支持向量 rotate 的子集上，可以用 `VPROLD` 减少 rotate-left 的指令数。
4. 掩码寄存器可以帮助处理不足 16 条消息的尾部 lane。

实验代码中的 `x86-avx512-512` 对应 16 lane multi-buffer 数据流。

## 代码实现

本目录提供一个可直接运行的脚本：

```text
python3 sm3_simd_hybrid_demo.py
```

主要函数包括：

```text
sm3_hash_scalar(message)
sm3_compress_scalar(state, block)
sm3_hash_many_simd(messages, lanes)
sm3_hash_simd_group(messages)
sm3_compress_simd(state, block_words_by_lane)
```

其中 `sm3_hash_many_simd` 按 lane 数对消息分组：

```python
ARCHITECTURE_LANES = {
    "arm64-neon-128": 4,
    "x86-avx2-256": 8,
    "x86-avx512-512": 16,
}
```

当一个 SIMD 分组内的消息填充后长度相同，就走 multi-buffer SIMD 模型；如果长度不匹配或尾部不足一个完整 SIMD 组，就自动退回标量实现。这对应真实工程中的常见策略：批量路径处理规则输入，零散尾部用标量路径收尾。

## 运行结果

在当前环境运行：

```text
python3 第四次实验/sm3_simd_hybrid_demo.py
```

得到示例输出：

```text
SM3 official abc test vector: ok
Hybrid register mapping
  general registers : loop counter, Tj selection, padding length, block address
  SIMD registers    : A..H state vectors, W/W' message schedule vectors
  arm64 target      : NEON EOR/AND/ORR/BIC/ADD/SHL/SRI or SM3 extensions when available
  x86 AVX2 target   : VPXOR/VPAND/VPOR/VPADDD/VPSLLD/VPSRLD across 8 lanes
  x86 AVX512 target : same data flow across 16 lanes with zmm registers
SM3 multi-buffer benchmark, 64 equal-length messages
  scalar general-register path : 0.0408s
  arm64-neon-128    lanes= 4: 0.0592s, correct=True
  x86-avx2-256      lanes= 8: 0.0533s, correct=True
  x86-avx512-512    lanes=16: 0.0495s, correct=True
  digest[0] = ed003a8dd3a5ce86ab411121de253bfc859b0191f5f17bff283bb9bacdffa261
```

在 Python 中，SIMD 模型不一定比标量快，因为 `list` lane 的解释器开销很大。这里更重要的是验证数据流：4/8/16 lane 的并行压缩结果和标量实现完全一致。迁移到 C/ASM 后，每个 lane 会落在真实 SIMD 寄存器里，吞吐量才会接近 lane 数带来的收益。

## 实验结论

本次实验可以总结为：

1. SM3 标量实现适合做正确性基准，已经通过 `SM3("abc")` 标准测试向量。
2. SM3 单消息轮间依赖强，主要优化方向不是拆一条消息，而是同时处理多条独立消息。
3. SIMD-hybrid 实现中，通用寄存器负责控制流、常量和地址，SIMD 寄存器负责 `A..H` 状态和 `W/W'` 消息扩展。
4. ARM64 NEON 可以实现 4 lane SM3，多数操作由 `EOR/AND/ORR/BIC/ADD/SHL/USHR` 组合完成；有 SM3 扩展时可以进一步使用专用指令。
5. x86 AVX2 可以实现 8 lane SM3，AVX512 可以实现 16 lane SM3，并可用 `VPTERNLOGD`、`VPROLD` 等指令减少布尔函数和循环移位开销。
6. Python 代码验证了 ARM64 与 x86 两类架构的数据流；实际性能提升需要使用 C/C++ intrinsic 或汇编实现。

## 参考资料

- GB/T 32905-2016：信息安全技术 SM3 密码杂凑算法
- GM/T 0004-2012：SM3 密码杂凑算法
- Arm Architecture Reference Manual：NEON、SM3 crypto extension
- Intel Intrinsics Guide：AVX2、AVX512、VPTERNLOGD、VPROLD
- RFC 8998：Use of the SM2 Signature Algorithm and SM3 Hash Algorithm in TLS 1.3
