# 第三次实验：对称密码算法的软件实现与优化

## 作业要求核对

本实验选择 SM4 作为分组密码实现对象，覆盖情况如下：

| 要求 | 完成情况 |
| --- | --- |
| 从基本实现出发优化对称密码软件效率 | 已实现 SM4 标量轮函数、T-table 轮函数、shuffle S-box 模型 |
| 覆盖 T-table | Python 与 C x86/ARM64 均实现 4 张 256 项 T-table |
| 覆盖 shuffle | Python 实现 nibble-row shuffle 模型，x86 C 实现 `PSHUFB` S-box 路径 |
| 覆盖最新指令集中的方法 | x86 C 给出 `PCLMULQDQ` GHASH 乘法核心，ARM64 C 给出 SM4E/SM4EKEY 与 PMULL 路径说明 |
| 优化 CTR/GCM/XTS 工作模式 | Python 完整实现 CTR、GCM、XTS，并复用轮密钥、实现 4-bit GHASH 表和 XTS tweak 更新 |

结论：Python 主程序是完整可运行实现；C 文件是面向 x86-64 与 ARM64 的 intrinsic 参考实现，其中 T-table 与 x86 `PSHUFB` 路径带测试向量，PCLMUL/PMULL/SM4E 作为对应指令集优化入口。

## 文件结构

```text
第三次实验/
├── README.md
├── Makefile
├── sm4_modes_optimization_demo.py
└── c_optimized/
    ├── sm4_x86_optimized.c
    └── sm4_arm_optimized.c
```

## 核心实现

`sm4_modes_optimization_demo.py` 包含：

1. SM4 密钥扩展、加密、解密。
2. 基础轮函数 `sm4_t_slow`。
3. T-table 轮函数 `sm4_t_table`，将 `SBOX + L` 预合并。
4. shuffle 轮函数 `sm4_t_shuffle`，用高/低 4 bit 行列选择模拟 SIMD 字节重排。
5. CTR、GCM、XTS 三种工作模式。
6. 官方 SM4 测试向量、模式往返测试和简单 benchmark。

模式优化点：

- CTR：计数器块相互独立，代码提供 `sm4_ctr_crypt_with_round_keys`，避免在 GCM 内部重复密钥扩展。
- GCM：CTR 加密复用轮密钥；GHASH 提供 bitwise 基准和 4-bit 预计算表。
- XTS：数据密钥和 tweak 密钥分离，tweak 通过 GF(2^128) 乘 `alpha` 更新。

`c_optimized/sm4_x86_optimized.c` 包含：

- T-table 单块加密。
- SSSE3 `PSHUFB` nibble-row S-box，并通过官方 SM4 向量测试。
- 8-block CTR 批处理接口，方便替换为 AVX2/AVX-512 多块轮函数。
- `PCLMULQDQ` 的 GHASH 乘法核心示例。

`c_optimized/sm4_arm_optimized.c` 包含：

- ARM64 可用的 T-table 实现。
- NEON `TBL/TBX` shuffle S-box 数据布局说明。
- ARMv8.4-A SM4E/SM4EKEY 与 PMULL 的优化路径说明。

## 运行方法

Python 验证：

```bash
python3 第三次实验/sm4_modes_optimization_demo.py
```

x86-64 C 编译：

```bash
cd 第三次实验
make sm4_x86_optimized
./sm4_x86_optimized
```

ARM64 C 交叉编译或 ARM64 本机编译：

```bash
cd 第三次实验
make sm4_arm_optimized
./sm4_arm_optimized
```

如果交叉编译器名称不同，可覆盖变量：

```bash
make sm4_arm_optimized AARCH64_CC=aarch64-linux-gnu-gcc
```

## 当前验证结果

当前环境已运行 Python 主程序，结果通过：

```text
SM4 official test vector: ok
Mode round-trip checks: CTR/GCM/XTS ok
```

当前环境已完成 C 验证：

```text
make -C 第三次实验 clean sm4_x86_optimized
./第三次实验/sm4_x86_optimized

SM4 T-table test vector:  PASS
SM4 PSHUFB test vector:   PASS
SM4 round-trip decrypt:   PASS
CTR round-trip:           PASS
XTS alpha update:         PASS
PCLMUL GHASH zero test:   PASS
```

同时用本机 gcc 编译 `sm4_arm_optimized.c` 的非 ARM fallback 路径，SM4 测试向量和解密测试均为 `PASS`。真正的 NEON/SM4E/PMULL 路径需要在 ARM64 机器或交叉编译环境中验证。

## 结论

本实验满足第三次作业的主要要求：SM4 基本实现、T-table、shuffle、指令集优化路径，以及 CTR/GCM/XTS 工作模式均已覆盖。完整可运行验证集中在 Python 实现；C 代码提供面向 x86-64/ARM64 的更接近真实工程实现的 intrinsic 版本和测试入口。

## 参考资料

- GB/T 32907-2016：信息安全技术 SM4 分组密码算法
- NIST SP 800-38A：Recommendation for Block Cipher Modes of Operation
- NIST SP 800-38D：Galois/Counter Mode (GCM) and GMAC
- NIST SP 800-38E：XTS-AES Mode for Confidentiality on Storage Devices
- Intel Intrinsics Guide：VPSHUFB、PCLMULQDQ、VPCLMULQDQ
- Arm Architecture Reference Manual：NEON、SM4E、SM4EKEY、PMULL
