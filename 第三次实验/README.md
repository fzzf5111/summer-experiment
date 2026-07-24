# 第三次实验：对称密码算法的软件实现与优化

## 题目

实现并优化 SM4 分组密码的软件实现，覆盖 T-table、shuffle、最新指令集优化方法，并结合 CTR、GCM、XTS 等工作模式分析优化思路。

## 结论摘要

本次实验的核心不是简单写出一个能加密的 SM4，而是分析“SM4 的计算结构为什么适合这些优化”。SM4 的一轮计算由非线性 S-box、线性变换 `L` 和轮密钥异或组成：

```text
X[i+4] = X[i] ^ T(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i])
T(x) = L(tau(x))
```

其中 `tau` 是 4 字节 S-box 替换，`L` 是循环移位和异或构成的线性扩散。优化的关键就是减少 `tau + L` 的重复计算、减少查表带来的缓存泄漏风险，并在工作模式层面把独立分组暴露给 SIMD 或专用指令。

本实验代码覆盖了三条路线：

1. T-table：把 `SBOX + L` 预计算成 4 张表，使一轮中的 4 次 S-box 和线性变换变成 4 次查表加异或。
2. shuffle S-box：把 8 bit 输入拆成高低 4 bit，用 SIMD shuffle 模拟 S-box，避免直接按密钥相关字节访问 256 项表。
3. 指令集优化：x86 侧给出 `PSHUFB`、`PCLMULQDQ` 路径，ARM64 侧给出 NEON `TBL/TBX`、SM4E/SM4EKEY、PMULL 的实现或接口位置。

CTR、GCM、XTS 的模式实现也放在实验重点里：这些模式的优化不是改变 SM4 算法本身，而是减少重复密钥扩展、批量处理独立分组，并使用 GF(2^128) 的快速乘法更新认证值或 tweak。

## SM4 算法背景

SM4 是 128 bit 分组密码，明文被拆成 4 个 32 bit 字：

```text
input = X0 || X1 || X2 || X3
```

每一轮用后三个状态字和轮密钥生成新状态：

```text
t = X1 ^ X2 ^ X3 ^ rk[i]
X4 = X0 ^ T(t)
```

轮结束后状态左移：

```text
X0, X1, X2, X3 <- X1, X2, X3, X4
```

32 轮结束后反序输出：

```text
cipher = X35 || X34 || X33 || X32
```

解密不需要另一套轮函数，只需要把轮密钥倒序使用：

```text
rk_dec[i] = rk[31 - i]
```

这也是代码中 `sm4_t_table_encrypt` 同时能用于加密和解密的原因。

## 代码结构

```text
第三次实验/
├── README.md
├── Makefile
├── sm4_modes_optimization_demo.py
└── c_optimized/
    ├── sm4_x86_optimized.c
    └── sm4_arm_optimized.c
```

`sm4_modes_optimization_demo.py` 是跨平台完整模型，负责验证算法正确性、工作模式正确性和优化数据流。C 文件用于展示更接近工程实现的 intrinsic 版本，其中 x86 文件覆盖 T-table、`PSHUFB` 和 `PCLMULQDQ`，ARM 文件覆盖 T-table fallback、NEON/SM4E/PMULL 路径。

## 代码思路：基础 SM4 实现

基础实现从标准定义出发，先实现四类函数：

```text
rotl32(x, n)       32 bit 循环左移
tau(x)             对 4 个字节分别查 S-box
L(x)               x ^ (x<<<2) ^ (x<<<10) ^ (x<<<18) ^ (x<<<24)
L_key(x)           x ^ (x<<<13) ^ (x<<<23)
```

加密轮函数使用 `L`，密钥扩展使用 `L_key`。两者都包含 S-box，但线性扩散不同，所以代码中保留了 `sm4_L` 和 `sm4_L_key` 两个函数。

密钥扩展的状态是 `K[0..35]`：

```text
K[0..3] = MK[0..3] ^ FK[0..3]
K[i+4] = K[i] ^ T'(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
rk[i] = K[i+4]
```

这里 `T' = L_key(tau(x))`。实现时先按大端序读入 16 字节密钥，再生成 32 个 32 bit 轮密钥。大端序处理是必要的，因为 SM4 标准测试向量按字节串给出，如果在小端机器上直接把 4 字节强转成 `uint32_t`，结果会错。

## 代码思路：T-table 优化

原始轮函数每轮需要：

```text
4 次 S-box 查表
4 个字节重新拼成 32 bit
4 次循环左移
多次 XOR
```

注意 `L` 是线性的，因此可以把每个字节位置对最终结果的贡献提前算好：

```text
T(x)
= L(SBOX[b0] << 24 | SBOX[b1] << 16 | SBOX[b2] << 8 | SBOX[b3])
= T0[b0] ^ T1[b1] ^ T2[b2] ^ T3[b3]
```

代码中的 `init_t_tables` 和 `sm4_init_t_tables` 就是在初始化阶段构造：

```text
T0[i] = L(SBOX[i] << 24)
T1[i] = L(SBOX[i] << 16)
T2[i] = L(SBOX[i] << 8)
T3[i] = L(SBOX[i])
```

这样每一轮核心变为：

```c
t = x1 ^ x2 ^ x3 ^ rk[i];
x0 ^= T0[(t >> 24) & 0xFF] ^
      T1[(t >> 16) & 0xFF] ^
      T2[(t >>  8) & 0xFF] ^
      T3[ t        & 0xFF];
```

T-table 的优势是减少指令数，适合普通 CPU；缺点是查表地址和中间值相关，真实密码库中要考虑 cache-timing 侧信道。因此本实验还实现了 shuffle S-box 路线。

## 代码思路：shuffle S-box

SM4 的 S-box 有 256 项，可以看成 16 行、16 列：

```text
input byte = high_nibble || low_nibble
SBOX[input] = row[high_nibble][low_nibble]
```

x86 版本用 `PSHUFB` 的思路处理：低 4 bit 作为行内索引，高 4 bit 选择哪一行。代码中 `shuffle_rows[16]` 保存 16 个 16 字节向量，每轮对 16 行都执行 shuffle，再用高 nibble 生成 mask 合并结果：

```text
lo = input & 0x0F
hi = input >> 4
for row in 0..15:
    selected = PSHUFB(shuffle_rows[row], lo)
    result |= selected & (hi == row)
```

这个写法在实验中强调数据流：S-box 不再表现为一次“按秘密字节访问 256 项表”的普通查表，而是用向量重排和掩码组合来表达。真实工程中还会进一步展开、合并、减少中间存储，并把多个分组一起处理。

ARM64 版本对应的是 NEON `TBL/TBX`。`TBL` 本质上也是向量查表，适合把一组字节输入同时映射到 S-box 输出。代码保留了 NEON 数据布局和替换点，并在非 ARM64 平台自动退回标量 T-table 路径。

## 代码思路：CTR、GCM、XTS 模式

CTR 模式把分组密码变成流加密：

```text
keystream_i = SM4_encrypt(counter_i)
cipher_i = plain_i ^ keystream_i
```

各个 `counter_i` 互不依赖，所以最适合多块并行。Python 代码里复用轮密钥；C 代码中 `sm4_ctr_8x_avx2` 暴露 8-block 批处理接口，当前核心仍调用 T-table 单块加密，但数据布局已经对应 AVX2/AVX512 多块轮函数。

GCM 由 CTR 加密和 GHASH 认证组成。GHASH 的核心是在 GF(2^128) 上做乘法：

```text
Y_i = (Y_{i-1} ^ X_i) * H
```

Python 实现中包含 bitwise 基准版和 4-bit 预计算表版。C 的 x86 路径给出 `PCLMULQDQ` 乘法核心，ARM64 路径给出 PMULL 核心。这里的优化点不是 SM4 轮函数，而是用 carry-less multiply 指令替代普通移位异或循环。

XTS 用于磁盘等按块加密场景。它为每个数据块引入 tweak：

```text
tweak_0 = E_k2(sector_number)
tweak_i = alpha * tweak_{i-1} in GF(2^128)
cipher_i = E_k1(plain_i ^ tweak_i) ^ tweak_i
```

代码中 `xts_mul_alpha` 完成 GF(2^128) 下乘 `alpha`，也就是左移一位，并在最高位溢出时异或约简常数 `0x87`。

## 代码运行结果

Python 主程序输出如下：

```text
SM4 official test vector: ok
Instruction-set mapping represented by this Python model
  x86 AVX2/AVX-512 : VPSHUFB-style S-box shuffle, vector lanes for CTR/XTS
  x86 VAES+PCLMUL  : AES/GCM analogue; VPCLMULQDQ maps to GHASH carry-less multiply
  ARMv8.4-A SM4    : SM4E/SM4EKEY for rounds and PMULL for GHASH
Mode round-trip checks
  CTR ciphertext prefix : bb51630374920dba57089a88ba6eb7cf
  GCM tag               : 83ca4ff7fcfcf0c1317a0f4e30d03e24
  XTS ciphertext prefix : f15a5951ac289522eeb2aa1f2d0b234d
SM4 block benchmark, 2048 blocks
  basic round   : 0.1061s, 0.29 MiB/s, checksum=11
  T-table round : 0.0355s, 0.88 MiB/s, checksum=11
  shuffle model : 0.1539s, 0.20 MiB/s, checksum=11
```

x86 C 优化版本输出如下：

```text
=== SM4 Optimized Implementation ===
Optimization methods:
  1. T-table (4KB precomputed, 4 lookups + 3 XORs per round)
  2. SSSE3/AVX2 shuffle (VPSHUFB, constant-time S-box)
  3. AVX2 + PCLMULQDQ (latest instruction set: CTR/GCM/XTS)

SM4 T-table test vector:  PASS
SM4 PSHUFB test vector:   PASS
SM4 round-trip decrypt:   PASS
CTR round-trip:           PASS
XTS alpha update:         PASS
PCLMUL GHASH zero test:   PASS

SM4 performance benchmark (T-table, 100000 blocks = ~1.5 MiB)
  T-table scalar:  0.0101 s,  151.17 MiB/s, checksum=73
  x86 optimization paths available:
    - SSSE3 VPSHUFB for constant-time S-box
    - AVX2 8-block parallel CTR
    - PCLMULQDQ for GHASH in GCM mode
    - VAES for AES-based modes (analogous to SM4 operations)
```

普通 C11 fallback 输出如下，用于说明没有打开 SIMD 编译开关时也能在 VSCode 中先跑通基础验证：

```text
=== SM4 Optimized Implementation ===
Optimization methods:
  1. T-table (4KB precomputed, 4 lookups + 3 XORs per round)
  2. SSSE3/AVX2 shuffle (VPSHUFB, constant-time S-box)
  3. AVX2 + PCLMULQDQ (latest instruction set: CTR/GCM/XTS)

SM4 T-table test vector:  PASS
SM4 round-trip decrypt:   PASS
CTR round-trip:           PASS
XTS alpha update:         PASS

SM4 performance benchmark (T-table, 100000 blocks = ~1.5 MiB)
  T-table scalar:  0.0112 s,  135.90 MiB/s, checksum=73
  x86 optimization paths available:
    - SSSE3 VPSHUFB path requires /arch:AVX2 or -mssse3
    - AVX2 8-block parallel CTR
    - PCLMULQDQ path requires /arch:AVX2 or -mpclmul
    - VAES for AES-based modes (analogous to SM4 operations)
```

ARM 文件在当前 x86 机器上走 fallback，输出如下：

```text
=== SM4 ARM64 NEON + Crypto Extension Optimized ===

(Compiled on non-ARM64; NEON/SM4E paths not available)

SM4 test vector: PASS
SM4 decrypt:     PASS

SM4 T-table benchmark (100000 blocks = ~1.5 MiB):
  T-table: 0.0113 s,  135.37 MiB/s, checksum=55
```

## 实验结论

本实验可以总结为：

1. SM4 的 T-table 优化来自线性变换 `L` 的可分解性，把 `tau + L` 合并后能显著减少每轮指令数。
2. T-table 虽快，但查表地址依赖中间值；shuffle S-box 用 SIMD 重排表达 S-box，是减少缓存侧信道风险的一条路线。
3. CTR、GCM、XTS 的优化重点在模式层：CTR 和 XTS 暴露多块并行，GCM 的 GHASH 可以用 PCLMULQDQ/PMULL 加速。
4. ARMv8.4-A 的 SM4E/SM4EKEY 能直接把 SM4 轮函数交给硬件执行，是比软件 S-box 更彻底的优化。
5. C 文件现在同时兼容 GCC/Clang/MSVC 的平台宏；Windows VSCode 默认配置下可以先运行标量 fallback，高指令集路径则由对应编译开关启用。

## 参考资料

- GB/T 32907-2016：信息安全技术 SM4 分组密码算法
- NIST SP 800-38A：Recommendation for Block Cipher Modes of Operation
- NIST SP 800-38D：Galois/Counter Mode (GCM) and GMAC
- NIST SP 800-38E：XTS-AES Mode for Confidentiality on Storage Devices
- Intel Intrinsics Guide：PSHUFB、PCLMULQDQ、VPCLMULQDQ
- Arm Architecture Reference Manual：NEON、SM4E、SM4EKEY、PMULL
