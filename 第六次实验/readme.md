# 第六次实验：密文卷积旋转次数最小性分析

## 题目

采用“打包、旋转、累加”策略，探索第五次实验中卷积实现的旋转次数是否达到理论最小值。

## 实验背景

第五次实验的卷积参数为：

```text
输入：单通道 4x4
卷积核：单输入单输出 3x3
步长：1
填充：无
输出：2x2
```

输出中每个元素都是 9 个输入槽位与 9 个明文权重的乘积之和。密文卷积的主要开销不是明文乘法和加法，而是 SIMD 槽位旋转，因为旋转需要 Galois key，且在真实 FHE 库中通常比普通加法更慢。

## 两种打包策略

本实验比较两种策略。

第一种是直接行主序打包：

```text
slot 0..15 = input[0][0], input[0][1], ..., input[3][3]
```

将输出保存在每个窗口左上角对应的槽位，即 `0, 1, 4, 5`。对于 `3x3` 卷积核，需要访问相对偏移：

```text
0, 1, 2,
4, 5, 6,
8, 9, 10
```

偏移 0 不需要旋转，其余 8 个非零偏移各需要一次旋转。因此直接行主序打包需要 8 次旋转。

第二种是 im2col 打包：

```text
block 0: output[0][0] 对应的 3x3 窗口
block 1: output[0][1] 对应的 3x3 窗口
block 2: output[1][0] 对应的 3x3 窗口
block 3: output[1][1] 对应的 3x3 窗口
```

每个 block 长度取 16，其中前 9 个槽位放窗口元素，后 7 个槽位补 0。密文乘以重复卷积核掩码后，每个 block 的前 9 个槽位就是 9 个乘积项。随后使用旋转距离 `1, 2, 4, 8` 做树形累加：

```text
acc = products
acc = acc + rot(acc, 1)
acc = acc + rot(acc, 2)
acc = acc + rot(acc, 4)
acc = acc + rot(acc, 8)
```

这样每个 block 首槽位累计了 9 个乘积项，即对应输出值。

## 理论最小值

对 im2col 打包后的单个输出窗口，最初每个槽位只包含 1 个乘积项。一次“旋转并相加”最多让某个槽位可包含的独立乘积项数量翻倍。因此经过 `r` 次旋转累加后，一个槽位最多能聚合：

```text
2^r
```

个独立项。一个 `3x3` 卷积输出需要聚合 9 项，所以旋转次数满足：

```text
2^r >= 9
r >= ceil(log2(9)) = 4
```

本实验的 im2col 实现正好使用 `1, 2, 4, 8` 共 4 次旋转，因此达到了该打包策略下的理论最小值。

需要注意：若固定使用原始 `4x4` 行主序输入打包，并把输出放在窗口左上角槽位，则理论最小值是 8 次旋转，因为 9 个卷积核位置对应 9 个不同位移，其中非零位移有 8 个，通用非零卷积核无法把这些位移合并为更少的旋转。

## 代码结构

```text
第六次实验/
├── readme.md
└── rotation_minimum_analysis.py
```

第五次实验中的 `seal_bfv_conv2d.cpp` 也用 Microsoft SEAL/BFV 实际执行了这两种打包策略，并打印真实同态旋转次数；本目录脚本负责把同一结论以更直接的槽位模型展开说明。

运行方式：

```bash
python3 第六次实验/rotation_minimum_analysis.py
```

也可以运行第五次实验的真实 SEAL 程序：

```bash
cd 第五次实验
make run
```

## 本机运行结果

```text
plain convolution:
[[348.0, 393.0], [528.0, 573.0]]

direct row-major packing:
  output: [[348.0, 393.0], [528.0, 573.0]]
  rotations used: 8
  theoretical minimum under this layout: 8
  reaches minimum: True

im2col block packing:
  output: [[348.0, 393.0], [528.0, 573.0]]
  rotations used: 4
  theoretical minimum under this layout: 4
  reaches minimum: True

verification: PASS
```

## 实验结论

在直接行主序输入打包下，本题卷积需要 8 次旋转，已经达到该固定布局的最小值。若允许在加密前采用 im2col 打包，把每个 `3x3` 窗口放入独立槽位块，则只需要 4 次旋转即可完成每个窗口的 9 项累加；由于 `ceil(log2(9)) = 4`，该实现达到了 im2col 打包策略下的理论最小值。
