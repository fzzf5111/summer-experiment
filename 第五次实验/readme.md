# 第五次实验：基于全同态加密库的密文卷积

## 题目

选择任一开源全同态加密库（CPU 或 GPU 均可），使用单输入单输出 `4x4` 输入和 `3x3` 卷积核（步长 1，无填充），实现密文卷积并验证结果正确性。

## 实验选择

本实验采用 Microsoft SEAL 4.1.2。SEAL 是开源 CPU 全同态加密库，支持 BFV、BGV、CKKS 等方案。本题的输入和卷积核都是整数，卷积只需要“密文加法、密文槽位旋转、密文乘明文权重”，因此选择 BFV batching 可以得到精确整数结果。

本地已从源码构建 SEAL，并安装到仓库本地 `.local` 目录。`.local` 是依赖安装目录，不提交到 GitHub；实验代码通过 CMake 的 `find_package(SEAL 4.1 REQUIRED)` 链接该库。

## 卷积参数

输入矩阵为：

```text
[[ 1,  2,  3,  4],
 [ 5,  6,  7,  8],
 [ 9, 10, 11, 12],
 [13, 14, 15, 16]]
```

卷积核为：

```text
[[1, 2, 3],
 [4, 5, 6],
 [7, 8, 9]]
```

步长为 1、无填充，因此输出大小为：

```text
(4 - 3) / 1 + 1 = 2
```

输出矩阵是 `2x2`。

## 明文基准结果

左上角窗口：

```text
1*1 + 2*2 + 3*3
+ 5*4 + 6*5 + 7*6
+ 9*7 + 10*8 + 11*9
= 348
```

完整明文卷积结果为：

```text
[[348, 393],
 [528, 573]]
```

## 代码结构

```text
第五次实验/
├── CMakeLists.txt
├── Makefile
├── fhe_conv2d_tenseal.py
├── readme.md
├── requirements.txt
└── seal_bfv_conv2d.cpp
```

`seal_bfv_conv2d.cpp` 是本次实验实际验证的 Microsoft SEAL/BFV 实现。`fhe_conv2d_tenseal.py` 是 TenSEAL 版本的 Python 实现，当前系统 Python 为 3.14，TenSEAL 暂无匹配 wheel，因此保留为可选路径。

## SEAL 参数

C++ 实现使用 BFV：

```text
scheme              BFV
poly_modulus_degree 8192
coeff_modulus       BFVDefault(8192)
plain_modulus       PlainModulus::Batching(8192, 20)
```

`BatchEncoder` 允许把多个整数打包到同一个密文的 SIMD 槽位中。加密后，卷积过程始终在密文对象上完成，只有最后为了验证才解密并解码输出槽位。

## 实现方法一：行主序直接打包

第一种实现把 `4x4` 输入按行主序放入槽位：

```text
slot 0..15 = input[0][0], input[0][1], ..., input[3][3]
```

输出保存在每个 `3x3` 窗口左上角对应槽位，即：

```text
0, 1, 4, 5
```

卷积核的 9 个位置相对左上角槽位的偏移为：

```text
0, 1, 2,
4, 5, 6,
8, 9, 10
```

偏移 0 不需要旋转，其余 8 个偏移分别执行一次 `Evaluator::rotate_rows`。每次旋转后使用明文 mask 只保留输出槽位，再乘以对应卷积核权重，最后把 9 个密文项累加。

## 实现方法二：im2col 打包

第二种实现把每个滑动窗口提前打包成一个槽位块。共有 4 个输出窗口，每个块长度为 16，前 9 个槽位保存窗口元素，后 7 个槽位补 0：

```text
block 0: output[0][0] 对应的 3x3 窗口
block 1: output[0][1] 对应的 3x3 窗口
block 2: output[1][0] 对应的 3x3 窗口
block 3: output[1][1] 对应的 3x3 窗口
```

密文乘以重复的卷积核明文 mask 后，每个块内前 9 个槽位就是 9 个乘积项。随后执行树形旋转累加：

```text
acc = products
acc = acc + rotate(acc, 1)
acc = acc + rotate(acc, 2)
acc = acc + rotate(acc, 4)
acc = acc + rotate(acc, 8)
```

每个块首槽位最终保存对应输出值。

## 构建与运行

如果已经安装 SEAL 到仓库 `.local`：

```bash
cd 第五次实验
make run
```

也可以手动构建：

```bash
cmake -S 第五次实验 -B /tmp/exp5-seal-build -DCMAKE_PREFIX_PATH=/mnt/e/暑期实验课/.local
cmake --build /tmp/exp5-seal-build
/tmp/exp5-seal-build/seal_bfv_conv2d
```

## 运行结果

本机真实 SEAL/BFV 运行结果：

```text
plain convolution:
[[348, 393], [528, 573]]
SEAL BFV direct row-major decrypted:
[[348, 393], [528, 573]]
direct row-major rotations: 8
SEAL BFV im2col decrypted:
[[348, 393], [528, 573]]
im2col rotations: 4
direct row-major theoretical minimum: 8
im2col theoretical minimum: 4
verification: PASS
```

## 实验结论

本实验使用 Microsoft SEAL 的 BFV batching 实现了 `4x4` 输入与 `3x3` 卷积核的密文卷积。两种打包方式解密后都得到：

```text
[[348, 393],
 [528, 573]]
```

与明文卷积完全一致。说明在卷积核为明文权重、输入为密文的场景下，可以通过“打包、旋转、明文乘法、累加”在密文域中正确完成卷积计算。
