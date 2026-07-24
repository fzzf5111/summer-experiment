# 第四次实验：SM3 软件实现与 SIMD 优化

## 作业要求核对

| 要求 | 完成情况 |
| --- | --- |
| 实现 SM3 软件算法 | 已实现 padding、消息扩展、压缩函数和 256-bit 摘要输出 |
| 基于 SIMD 寄存器和通用寄存器混合优化 | Python 与 C 均采用 multi-buffer 设计：通用寄存器控制循环/地址/常量，SIMD 寄存器保存 A..H 和 W/W' |
| 覆盖 ARM64 指令集 | C 文件实现 ARM64 NEON 4-lane multi-buffer 路径，并说明 SM3 crypto extension |
| 覆盖 x86 AVX2/AVX512 指令集 | C 文件实现 AVX2 8-lane 与 AVX512 16-lane multi-buffer 压缩/哈希路径 |
| 正确性验证 | Python 通过 `SM3("abc")` 官方向量，并比较 4/8/16 lane SIMD 模型与标量结果 |

结论：本实验满足第四次作业要求。Python 是可跨平台运行的数据流模型，C 文件给出 ARM64 NEON、x86 AVX2、x86 AVX512 的 intrinsic 实现和自测入口。

## 文件结构

```text
第四次实验/
├── README.md
├── Makefile
├── sm3_simd_hybrid_demo.py
└── c_optimized/
    ├── sm3_x86_simd.c
    └── sm3_arm_neon.c
```

## 实现思路

SM3 单条消息的 64 轮压缩存在强依赖，后一轮依赖上一轮的 A..H 状态。因此本实验采用 multi-buffer SIMD：同时处理多条独立消息，每条消息占一个 SIMD lane。

通用寄存器负责：

- 轮计数 `j`。
- `Tj` 常量选择。
- 消息分组地址和 padding 长度。
- 循环分支和尾部处理。

SIMD 寄存器负责：

- `A, B, C, D, E, F, G, H` 状态向量。
- `W[0..67]` 消息扩展向量。
- `W'[0..63]` 辅助消息向量。

## 架构映射

| 操作 | ARM64 NEON | x86 AVX2 | x86 AVX512 |
| --- | --- | --- | --- |
| lane 数 | 4 × 32-bit | 8 × 32-bit | 16 × 32-bit |
| XOR | `EOR` | `VPXOR` | `VPXORD` |
| AND/OR | `AND/ORR/BIC` | `VPAND/VPOR/VPANDN` | `VPANDD/VPORD/VPANDND` |
| 加法 | `ADD` | `VPADDD` | `VPADDD` |
| 循环左移 | shift + or | `VPSLLD+VPSRLD+VPOR` | `VPROLD` 或 shift + or |
| 三输入布尔 | 逻辑组合 | 逻辑组合 | `VPTERNLOGD` |
| 专用扩展 | 可选 SM3SS1/SM3TT/SM3PARTW | 无 | 无 |

## 代码说明

`sm3_simd_hybrid_demo.py`：

- `sm3_hash_scalar` 是标量正确性基准。
- `sm3_compress_simd` 用 `list[int]` 表示 SIMD lane。
- `sm3_hash_many_simd` 根据 lane 数分组，长度不匹配或尾部不足时回退标量。
- `ARCHITECTURE_LANES` 映射 ARM64 NEON、AVX2、AVX512 的 lane 数。

`c_optimized/sm3_x86_simd.c`：

- `sm3_hash_avx2_8x`：AVX2 8-lane multi-buffer。
- `sm3_hash_avx512_16x`：AVX512 16-lane multi-buffer。
- 主函数包含官方向量、AVX2/AVX512 与标量结果比较。

`c_optimized/sm3_arm_neon.c`：

- `sm3_hash_neon_4x`：ARM64 NEON 4-lane multi-buffer。
- 主函数在 ARM64 上比较 NEON 与标量结果。
- 注释中给出 SM3 crypto extension 的替换位置。

## 运行方法

Python 验证：

```bash
python3 第四次实验/sm3_simd_hybrid_demo.py
```

x86 AVX2：

```bash
cd 第四次实验
make sm3_x86_simd
./sm3_x86_simd
```

x86 AVX512：

```bash
cd 第四次实验
make sm3_x86_avx512
./sm3_x86_avx512
```

ARM64 NEON：

```bash
cd 第四次实验
make sm3_arm_neon
./sm3_arm_neon
```

如果交叉编译器名称不同，可覆盖变量：

```bash
make sm3_arm_neon AARCH64_CC=aarch64-linux-gnu-gcc
```

## 当前验证结果

当前环境已运行 Python 主程序，结果通过：

```text
SM3 official abc test vector: ok
arm64-neon-128 lanes=4: correct=True
x86-avx2-256 lanes=8: correct=True
x86-avx512-512 lanes=16: correct=True
```

当前环境已完成 C 编译和可运行路径验证：

```text
make -C 第四次实验 clean sm3_x86_simd sm3_x86_avx512
./第四次实验/sm3_x86_simd

SM3("abc") test: PASS
AVX2 8-lane multi-buffer test: PASS
```

`sm3_x86_avx512` 已编译通过，但当前 CPU flags 只有 `avx2`、`vaes`、`vpclmulqdq` 等，没有 `avx512*`，运行 AVX512 二进制会以退出码 132 结束。因此 AVX512 路径在本机只能完成编译验证，运行验证需要支持 AVX512 的机器。

`sm3_arm_neon.c` 已用本机 gcc 编译非 ARM fallback 路径，`SM3("abc")` 为 `PASS`。真正的 NEON 4-lane 路径需要在 ARM64 机器或交叉编译环境中验证。

## 结论

SM3 的优化重点是多消息并行，而不是拆开单条消息的轮依赖。本实验用 Python 验证 multi-buffer 数据流，用 C intrinsic 对应 ARM64 NEON、x86 AVX2 和 x86 AVX512，实现了 SIMD 寄存器与通用寄存器混合的 SM3 软件优化方案。

## 参考资料

- GB/T 32905-2016：信息安全技术 SM3 密码杂凑算法
- GM/T 0004-2012：SM3 密码杂凑算法
- Arm Architecture Reference Manual：NEON、SM3 crypto extension
- Intel Intrinsics Guide：AVX2、AVX512、VPTERNLOGD、VPROLD
- RFC 8998：Use of the SM2 Signature Algorithm and SM3 Hash Algorithm in TLS 1.3
