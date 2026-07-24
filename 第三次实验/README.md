# 暑期实验课实验：第三次实验

## 题目

对称密码算法的软件实现：

从基本实现出发，优化对称密码（SM4/AES/GIFT/TWINE）的软件执行效率，至少应该覆盖 T-table、shuffle 以及最新的指令集中的两种方法。

基于加解密软件实现，做 CTR/GCM/XTS 工作模式的软件优化实现。

## 结论摘要

本次实验选取 SM4 作为主要实现对象。SM4 和 AES 一样是 128-bit 分组密码，轮函数中有非线性 S 盒和线性扩散层，因此很适合展示从基础实现到查表、shuffle 和指令集优化的演进过程。

实验代码实现了三条 SM4 加密路径：

1. 基础实现：逐字节 S 盒替换，再执行线性变换。
2. T-table 实现：把 S 盒替换和线性变换预合并为 4 张 256 项查表。
3. shuffle 模型：用高 4 bit/低 4 bit 的行列选择模拟 SIMD 中 `VPSHUFB/TBL` 一类字节重排查表。

同时实现了三种常见工作模式：

1. CTR：分组计数器独立加密，可天然并行。
2. GCM：CTR 加密加 GHASH 认证，代码中实现了 bitwise GHASH 和 4-bit 表驱动 GHASH。
3. XTS：面向磁盘扇区加密，用第二个密钥生成 tweak，并对每个分组做 GF(2^128) 中的乘 `alpha` 更新。

在真实高性能实现中，T-table 往往适合通用 CPU 的早期优化；shuffle 更适合 AVX2/AVX-512/NEON 这类 SIMD 寄存器；最新指令集可以进一步使用 x86 的 AES-NI/VAES、PCLMULQDQ/VPCLMULQDQ，以及 ARMv8.4-A 的 SM4E/SM4EKEY、PMULL。Python 代码不能直接发出这些机器指令，因此本实验代码提供的是可验证的算法模型和优化结构，报告中给出对应到 C/ASM intrinsic 的实现方式。

## 背景：SM4 分组密码结构

SM4 的分组长度和密钥长度都是 128 bit。加密过程使用 32 轮迭代，每轮输入 4 个 32-bit 字：

```text
X0, X1, X2, X3
```

第 `i` 轮计算：

```text
Xi+4 = Xi xor T(Xi+1 xor Xi+2 xor Xi+3 xor rki)
```

其中轮函数 `T` 由两个部分组成：

```text
T(A) = L(tau(A))
```

`tau` 是 4 个字节上的 S 盒替换：

```text
tau(A) = SBOX(a0) || SBOX(a1) || SBOX(a2) || SBOX(a3)
```

`L` 是线性扩散层：

```text
L(B) = B xor (B <<< 2) xor (B <<< 10) xor (B <<< 18) xor (B <<< 24)
```

密钥扩展也使用类似结构，但线性层不同：

```text
L'(B) = B xor (B <<< 13) xor (B <<< 23)
```

解密不需要写一个新的反向轮函数，只需要把 32 个轮密钥逆序使用即可。

## 基础实现

最直接的软件实现就是严格照公式写：

```python
def sm4_tau(word: int) -> int:
    return (
        (SBOX[(word >> 24) & 0xFF] << 24)
        | (SBOX[(word >> 16) & 0xFF] << 16)
        | (SBOX[(word >> 8) & 0xFF] << 8)
        | SBOX[word & 0xFF]
    )

def sm4_l(word: int) -> int:
    return word ^ rotl32(word, 2) ^ rotl32(word, 10) ^ rotl32(word, 18) ^ rotl32(word, 24)

def sm4_t_slow(word: int) -> int:
    return sm4_l(sm4_tau(word))
```

这种写法的优点是结构清晰，容易和标准公式对照。缺点是每轮都要做 4 次 S 盒访问、多个移位、多个异或。SM4 一次分组加密有 32 轮，因此基础实现的解释器开销和位运算开销都比较明显。

## T-table 优化

SM4 的 `tau` 和 `L` 都作用在同一个 32-bit 字上，而且 `L` 是线性的。因此可以把每个字节位置的 S 盒输出对最终 `L` 的贡献提前算好：

```text
T(A) = T0[a0] xor T1[a1] xor T2[a2] xor T3[a3]
```

其中：

```text
T0[x] = L(SBOX[x] << 24)
T1[x] = L(SBOX[x] << 16)
T2[x] = L(SBOX[x] << 8)
T3[x] = L(SBOX[x])
```

代码中的实现为：

```python
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
```

T-table 的代价是增加 4 KB 左右的常量表，收益是把一轮中的 S 盒、移位和异或合并成 4 次查表和 3 次异或。在 C 语言中这通常能显著减少指令数。

不过 T-table 会让访存地址依赖秘密数据。在需要抗 cache timing 侧信道的场景中，不能只追求速度，还要考虑常数时间实现、bitslice、shuffle 或专用指令。

## Shuffle 优化

shuffle 优化的核心思想是把多个分组的多个字节放进 SIMD 寄存器，用字节重排指令做并行 S 盒替换。

例如 x86 SSSE3/AVX2/AVX-512 中的 `PSHUFB/VPSHUFB` 可以根据每个字节的低 4 bit 从 16 字节表中选择元素。对于 8-bit S 盒，常见做法是把输入拆成高 4 bit 和低 4 bit，再通过多轮 shuffle、掩码和组合完成查表。ARM NEON 中也可以用 `TBL/TBX` 做类似工作。

本实验代码中的 `sbox_shuffle_bytes` 是一个 Python 层面的结构模拟：

```python
SBOX_ROWS = tuple(bytes(SBOX[i : i + 16]) for i in range(0, 256, 16))

def sbox_shuffle_bytes(data: bytes) -> bytes:
    return bytes(SBOX_ROWS[value >> 4][value & 0x0F] for value in data)
```

它不代表 Python 会真的使用 SIMD，但它对应的机器级思路是：

```text
high_nibble = input >> 4
low_nibble  = input & 0x0f
row_table   = select table by high_nibble
output      = shuffle(row_table, low_nibble)
```

shuffle 方法比 T-table 更适合多块并行，因为 128-bit、256-bit、512-bit SIMD 寄存器可以一次处理多个 SM4 轮函数中的字节。对于 CTR、GCM 的 CTR 部分、XTS 中的多个数据块，这种并行性尤其直接。

## 最新指令集优化方法

本实验覆盖两类最新指令集优化路径。

### 1. x86：AES-NI/VAES 与 PCLMULQDQ/VPCLMULQDQ

如果选择 AES 作为分组密码，x86 上最直接的优化是：

```text
AESENC/AESDEC/AESKEYGENASSIST
VAESENC/VAESDEC
PCLMULQDQ/VPCLMULQDQ
```

AES-NI 和 VAES 把 AES 轮函数直接做成硬件指令，避免普通查表 S 盒带来的 cache timing 风险。GCM 的 GHASH 是 GF(2^128) 上的多项式乘法，`PCLMULQDQ` 和 `VPCLMULQDQ` 可以做 carry-less multiply，是 AES-GCM 高性能实现的核心。

如果仍然实现 SM4，在没有 x86 原生 SM4 指令时，可以使用 AVX2/AVX-512 的 shuffle、ternary logic、rotate/shift 组合做多块并行。对应关系是：

```text
S box       -> VPSHUFB + mask/logic
linear L    -> VPSLLD/VPSRLD/VPROLD + VPXOR
CTR/XTS     -> vector counter/tweak lanes
GCM GHASH   -> VPCLMULQDQ
```

### 2. ARM64：SM4E/SM4EKEY 与 PMULL

ARMv8.4-A 引入了 SM4 专用指令：

```text
SM4E
SM4EKEY
```

`SM4E` 用于执行 SM4 加密轮，`SM4EKEY` 用于密钥扩展轮。这样可以避免软件 S 盒和线性层组合的开销，也减少基于查表的侧信道风险。

GCM 中的 GHASH 可以使用 ARM 的 `PMULL/PMULL2` 做 carry-less multiply：

```text
SM4 block encryption -> SM4E
GHASH multiplication -> PMULL
```

因此，ARM64 上的 SM4-GCM 可以形成完整的硬件辅助路径。

## CTR 模式优化

CTR 模式把分组密码变成流加密：

```text
Si = E_K(Nonce || counter_i)
Ci = Pi xor Si
```

每个计数器块之间没有依赖关系，所以可以批量生成：

```text
counter_0, counter_1, counter_2, counter_3
```

然后一次用 SIMD/指令集并行加密多个 counter。CTR 解密和加密完全相同，只需要再次异或同一段密钥流。

代码中 `sm4_ctr_crypt` 接收一个增量函数，普通 CTR 使用 128-bit counter 递增，GCM 内部使用低 32-bit 递增：

```python
def sm4_ctr_crypt(data, key, iv, transform=sm4_t_table, increment=inc128):
    ...
```

## GCM 模式优化

GCM 由两部分组成：

```text
encryption: CTR
authentication: GHASH
```

GHASH 的核心是：

```text
Y_i = (Y_{i-1} xor X_i) * H  in GF(2^128)
```

其中：

```text
H = E_K(0^128)
```

基础 GHASH 可以逐 bit 做有限域乘法，但速度较慢。实验代码中实现了 4-bit 预计算表：

```python
def build_ghash_4bit_tables(h: int) -> list[list[int]]:
    tables = []
    for pos in range(32):
        shift = 124 - 4 * pos
        tables.append([gf_mul_bitwise(nibble << shift, h) for nibble in range(16)])
    return tables
```

因为 GF(2^128) 乘法对输入是线性的，所以可以把 128-bit 输入拆成 32 个 nibble，分别查表后异或合并。

真实 x86/ARM 高性能实现会进一步用 `PCLMULQDQ/VPCLMULQDQ` 或 `PMULL` 替代软件查表，并用 Karatsuba 和延迟约简减少指令数。

## XTS 模式优化

XTS 常用于磁盘和扇区加密。它使用两个密钥：

```text
K1: 数据加密密钥
K2: tweak 加密密钥
```

每个扇区先计算初始 tweak：

```text
T0 = E_K2(sector_number)
```

每个数据块加密为：

```text
Ci = E_K1(Pi xor Ti) xor Ti
Ti+1 = alpha * Ti
```

其中 `alpha * Ti` 是 GF(2^128) 上的乘法。代码中的 full-block XTS 实现为：

```python
mixed = xor_bytes(block, tweak)
crypted = sm4_crypt_block(mixed, data_round_keys, transform)
output.extend(xor_bytes(crypted, tweak))
tweak = xts_mul_alpha(tweak)
```

XTS 的数据块加密彼此只依赖 tweak 序列。实际优化时可以先批量计算多个 tweak，再将多个 `(Pi xor Ti)` 放入 SIMD 寄存器并行加密。

本实验代码为了保持简洁，只实现完整 16 字节分组的 XTS；工程实现中还需要补上最后一个非完整分组的 ciphertext stealing。

## 代码实现

本目录提供两类实现，覆盖 T-table、shuffle、最新指令集三种优化方法：

### Python 算法模型

可直接运行验证算法正确性：

```bash
python3 sm4_modes_optimization_demo.py
```

### C 优化实现（真机 intrinsic）

| 文件 | 目标架构 | 优化方法 | 编译命令 |
|------|---------|---------|--------|
| `c_optimized/sm4_x86_optimized.c` | x86-64 | T-table + SSSE3 shuffle + AVX2/PCLMUL | `make sm4_x86_optimized` |
| `c_optimized/sm4_arm_optimized.c` | ARM64 | T-table + NEON TBL shuffle + SM4E | `make sm4_arm_optimized` |

编译要求：

```bash
# x86-64 (需支持 SSSE3 + AVX2 + PCLMUL)
cd 第三次实验 && make sm4_x86_optimized && ./sm4_x86_optimized

# ARM64 (需 NEON，可选 SM4E)
cd 第三次实验 && make sm4_arm_optimized && ./sm4_arm_optimized
```

C 代码中三条优化路径的真实指令映射：

| 优化方法 | x86-64 指令 | ARM64 指令 |
|---------|------------|----------|
| T-table | 标量查表 (MOV + XOR) | 标量查表 (LDR + EOR) |
| Shuffle | `VPSHUFB` (SSSE3), `VPSHUFB` (AVX2) | `TBL`/`TBX` (NEON) |
| 最新指令集 | `VPCLMULQDQ` (GHASH), `VAESENC` (AES) | `SM4E`/`SM4EKEY`, `PMULL` (GHASH) |

脚本内容包括：

1. SM4 基础轮函数、T-table 轮函数、shuffle 模型轮函数。
2. SM4 密钥扩展、加密、解密。
3. CTR、GCM、XTS 三种工作模式。
4. SM4 官方测试向量校验。
5. 三条轮函数路径的小型性能对比。
6. x86/ARM 指令集优化路径的对应关系输出。

核心测试向量为：

```text
key       = 0123456789abcdeffedcba9876543210
plaintext = 0123456789abcdeffedcba9876543210
cipher    = 681edf34d206965e86b3e94f536e4246
```

## 运行结果

在当前环境运行：

```text
python3 第三次实验/sm4_modes_optimization_demo.py
```

得到示例输出：

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
  basic round   : 0.0526s, 0.59 MiB/s, checksum=11
  T-table round : 0.0211s, 1.48 MiB/s, checksum=11
  shuffle model : 0.0711s, 0.44 MiB/s, checksum=11
```

从结果可以看到，T-table 路径在 Python 中也能体现出减少轮函数运算量的效果。shuffle 模型在 Python 中并不快，因为它只是模拟 SIMD 查表结构，没有真正使用 SIMD 寄存器；在 C/ASM 中使用 AVX2/AVX-512/NEON 后，它的优势主要来自多分组并行和更好的常数时间特性。

## 实验结论

本次实验可以总结为：

1. SM4 基础实现最适合理解算法结构，但每轮的 S 盒和线性层开销较高。
2. T-table 能把 `tau` 和 `L` 预合并，减少运行时指令数，但需要注意 cache timing 侧信道。
3. shuffle 方法把 S 盒替换转化为 SIMD 字节重排，适合 AVX2、AVX-512 和 NEON 的多块并行实现。
4. 最新指令集优化可以分为 x86 的 AES-NI/VAES/PCLMULQDQ/VPCLMULQDQ 路径，以及 ARM64 的 SM4E/SM4EKEY/PMULL 路径。
5. CTR、GCM、XTS 都能从分组并行中受益；GCM 的额外瓶颈是 GHASH，因此需要 carry-less multiply 或表驱动乘法优化。
6. Python 代码验证了算法正确性和优化结构；真正的性能优化需要在 C/C++ 或汇编中调用对应的 CPU intrinsic。

## 参考资料

- GB/T 32907-2016：信息安全技术 SM4 分组密码算法
- NIST SP 800-38A：Recommendation for Block Cipher Modes of Operation
- NIST SP 800-38D：Galois/Counter Mode (GCM) and GMAC
- NIST SP 800-38E：XTS-AES Mode for Confidentiality on Storage Devices
- Intel Intrinsics Guide：AES-NI、VAES、PCLMULQDQ、VPCLMULQDQ、VPSHUFB
- Arm Architecture Reference Manual：SM4E、SM4EKEY、PMULL
