# 暑期实验课实验：第二次实验

## 题目

检查 [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) 仓库，分析 Bitcoin 中 ECDSA 相关的漏洞修复、性能改进，以及背后的数学原因。

## 结论摘要

本次实验找到的核心问题不是 `secp256k1` 当前实现里可以直接利用的漏洞，而是 ECDSA 的一个重要 API 使用陷阱：如果验证程序只验证一个外部给出的 32 字节消息哈希 `e`，却没有检查它是否确实由被声明的消息 `m` 计算得到，即 `e = hash(m)`，攻击者可以构造一个能通过验证的签名。

`libsecp256k1` 的接口也专门提醒调用者：ECDSA 签名/验证函数处理的是 32 字节消息哈希，调用者必须先对真实消息使用密码学哈希，并在需要时做上下文绑定或域分离。也就是说，库只负责验证 `(e, signature, public key)` 之间的椭圆曲线关系；“这个 `e` 是否对应真实消息”是上层协议必须保证的事情。

在 Bitcoin 中，正确做法是由共识代码根据交易内容和 `SIGHASH` 规则计算待签名哈希，再调用 secp256k1 验证签名，而不是让用户任意提交一个 hash 让系统相信它代表某条交易。

## 背景：ECDSA 签名与验证

设椭圆曲线基点为 `G`，阶为 `n`，私钥为 `d`，公钥为：

```text
P = dG
```

对消息 `m` 签名时：

```text
e = hash(m)
k <- Z_n*
R = kG = (x_R, y_R)
r = x_R mod n
s = k^(-1)(e + dr) mod n
signature = (r, s)
```

验证签名 `(r, s)` 时：

```text
e = hash(m)
w = s^(-1) mod n
u1 = ew mod n
u2 = rw mod n
X = u1G + u2P
valid iff x_X mod n == r
```

正确签名为什么能通过验证：

```text
s = k^(-1)(e + dr)
s^(-1) = k(e + dr)^(-1)

s^(-1)(eG + rP)
= s^(-1)(eG + rdG)
= s^(-1)(e + dr)G
= kG
= R
```

因此验证得到的点就是签名时的 `R`，所以 `x_R mod n == r`。

## 漏洞点：只验证 hash，不验证消息绑定

如果系统把 `e` 当成外部输入，并且只检查：

```text
s^(-1)(eG + rP) = R
```

却没有检查：

```text
e == hash(m)
```

那么攻击者可以在不知道私钥 `d` 的情况下构造一个可通过验证的三元组 `(e', r', s')`。

构造方法如下：

```text
choose u, v in Z_n*
R' = uG + vP = (x', y')
r' = x' mod n
s' = r'v^(-1) mod n
e' = r'u v^(-1) mod n
```

验证时：

```text
s'^(-1)e'
= (r'v^(-1))^(-1) * (r'u v^(-1))
= vr'^(-1) * r'u v^(-1)
= u

s'^(-1)r'
= (r'v^(-1))^(-1) * r'
= vr'^(-1)r'
= v
```

所以验证计算的点为：

```text
s'^(-1)(e'G + r'P)
= s'^(-1)e'G + s'^(-1)r'P
= uG + vP
= R'
```

而攻击者一开始就令：

```text
r' = x(R') mod n
```

因此 `(r', s')` 会成为 `e'` 上的有效 ECDSA 签名。整个过程中攻击者没有用到私钥 `d`。

这个伪造不是说攻击者能随意伪造某个指定消息 `m` 的签名，因为要找到 `hash(m) = e'` 的原像仍然很困难。真正的问题是：如果业务系统没有把签名验证和真实消息绑定，只验证一个提交上来的 hash，那么攻击者可以伪造“某个 hash 的有效签名”，并冒充公钥持有人。

## 在 secp256k1 仓库中的对应位置

`bitcoin-core/secp256k1` 的核心 API 是围绕 32 字节消息哈希设计的。例如：

- `secp256k1_ecdsa_sign` 接收 `msghash32`；
- `secp256k1_ecdsa_verify` 也接收 `msghash32`；
- 文档提醒调用方必须先对真实消息做密码学哈希，不能直接把任意可变长消息或未绑定上下文的数据交给 ECDSA。

这说明 `libsecp256k1` 的安全边界是：验证“某个 32 字节摘要上的签名是否对应某个公钥”。它不会也不可能自动知道这个摘要来自哪一笔 Bitcoin 交易、哪个脚本上下文或哪个业务消息。

因此，本实验中的漏洞应写作：

```text
漏洞类型：ECDSA 调用方未检查 signed message 与 message hash 的绑定关系。
影响：攻击者可构造能通过验证的 (e', r', s')，从而冒充公钥持有人签过某个 hash。
根因：ECDSA 验证公式只检查椭圆曲线代数关系；如果 e 不由验证方从真实消息计算，而是由攻击者提供，就失去了消息认证语义。
修复：验证方必须自己计算 e = H(domain || context || message)，再把 e 传给 secp256k1_ecdsa_verify。
```

## Bitcoin 中的修复思路

Bitcoin 对 ECDSA 的使用不应是“用户给 hash，节点验证 hash 的签名”。正确流程是：

```text
transaction + script context + sighash flag
        |
        v
Bitcoin consensus code computes signature digest
        |
        v
libsecp256k1 verifies ECDSA signature over that digest
```

这样签名就绑定到了具体交易、输入、输出、金额、脚本和 `SIGHASH` 语义上。攻击者不能只构造一个随机的 `e'` 来骗过节点，因为节点会根据交易内容重新计算摘要。

Bitcoin Core 后来将签名验证从 OpenSSL 迁移到 `libsecp256k1`，这同时解决了两个问题：

1. 共识安全：OpenSSL 是通用 TLS/密码库，不保证不同版本之间的 ECDSA/DER 解析行为永远一致。Bitcoin 共识规则需要所有节点对同一笔交易得到完全一致的验签结果。
2. 性能：Bitcoin 节点在验证区块时要执行大量 ECDSA 签名验证，专门为 secp256k1 曲线优化的库比通用库更合适。

BIP66 要求严格 DER 编码，目的也是减少签名解析差异带来的共识风险。Bitcoin Core 0.12 开始使用 `libsecp256k1` 做 ECDSA 签名验证，进一步减少了依赖 OpenSSL 造成的风险。

## 相关修复：ECDSA 签名可延展性

ECDSA 还有一个与 Bitcoin 交易安全直接相关的问题：如果 `(r, s)` 是有效签名，那么 `(r, n - s)` 通常也是有效签名。

原因是：

```text
s2 = n - s = -s mod n
s2^(-1) = -s^(-1) mod n
```

验证点会从：

```text
R = s^(-1)(eG + rP)
```

变成：

```text
R2 = -s^(-1)(eG + rP) = -R
```

椭圆曲线上 `R` 和 `-R` 的 `x` 坐标相同，所以：

```text
x(R2) mod n == x(R) mod n == r
```

这意味着攻击者可以不改变交易含义，只改变签名字节，从而改变交易 ID 相关的数据。这类问题称为签名可延展性。`libsecp256k1` 的 ECDSA 验证默认只接受 lower-S 签名，并提供签名归一化接口，从库层面帮助上层减少这种可延展性。

## 性能改进：为什么 libsecp256k1 更快

Bitcoin 中最频繁的密码学操作之一是验证交易签名。ECDSA 验证的主要开销在这个多标量乘法：

```text
u1G + u2P
```

其中 `G` 是固定基点，`P` 是用户公钥。`libsecp256k1` 针对这个结构做了专门优化。

### 1. 固定基点预计算

`G` 永远是 secp256k1 曲线的固定生成元，因此可以预计算很多 `G` 的倍点。验证时计算 `u1G` 不需要从零开始做完整标量乘法。

数学上，标量 `u1` 可以拆成窗口表示：

```text
u1 = sum_i a_i 2^(wi)
```

于是：

```text
u1G = sum_i a_i (2^(wi)G)
```

预先保存 `2^(wi)G` 或窗口表后，运行时只需要查表、点加和点倍乘，减少大量重复计算。

### 2. wNAF 与 Shamir/Straus 技巧

ECDSA 验证需要同时算两个乘法：

```text
u1G + u2P
```

如果分开计算，需要两次标量乘法再相加。Shamir/Straus 技巧把两个标量的扫描合并，在同一轮倍点过程中根据窗口位选择加 `G`、加 `P` 或两者的组合。

直观上，原来是：

```text
compute u1G
compute u2P
add them
```

优化后是：

```text
scan bits/windows of u1 and u2 together
perform one combined multiplication loop
```

wNAF（windowed non-adjacent form）进一步减少非零项数量，从而减少昂贵的椭圆曲线点加次数。

### 3. secp256k1 曲线的 GLV endomorphism

secp256k1 曲线有特殊结构，可以使用高效自同态：

```text
phi(P) = lambda P
```

其中 `phi` 在坐标上计算很快。利用这个性质，可以把一个 256 位标量乘法拆成两个约 128 位标量乘法：

```text
kP = k1P + k2 phi(P)
```

较短的标量意味着更少的倍点和点加操作。这是 secp256k1 相比随机曲线能被高度优化的原因之一。

### 4. 有限域与标量运算专门优化

secp256k1 使用的素数域为：

```text
p = 2^256 - 2^32 - 977
```

这个素数形状适合快速模约简。`libsecp256k1` 不是调用通用大整数库，而是用固定大小 limb 表示、专门的模加/模乘/模约简代码以及常数时间实现来减少开销和侧信道风险。

### 5. Jacobian 坐标减少求逆

仿射坐标点加法常常需要有限域求逆，而求逆比乘法贵很多。Jacobian 坐标把点写成：

```text
(X, Y, Z) represents (X/Z^2, Y/Z^3)
```

中间点加和倍点可以主要用乘法完成，最后再做一次求逆转回仿射坐标。这样能显著降低签名验证中的总成本。

## 为什么这些改进对 Bitcoin 很重要

Bitcoin 节点验证新区块时，每个输入脚本里的签名都可能触发一次或多次 ECDSA 验证。假设一个区块里有大量签名，验证成本近似为：

```text
total_cost ~= number_of_signatures * cost(ECDSA_verify)
```

因此，即使单次验证只快几倍，整体区块验证时间也会明显下降。更快的验证还能降低节点运行成本，使更多用户能够运行全节点，间接增强网络去中心化。

安全层面，Bitcoin 的共识代码必须保证“相同输入得到相同验签结果”。通用库可能因为版本升级改变 DER 容错行为、边界条件或解析细节，而专用的 `libsecp256k1` 可以把这些行为固定在 Bitcoin 需要的规则内。

## 代码实现

本目录提供了一个最小可运行脚本：

```text
python3 ecdsa_hash_forgery_demo.py
```

代码没有依赖第三方库，直接实现 secp256k1 的有限域运算、椭圆曲线点加、标量乘法和 ECDSA 验证。它演示的不是破解私钥，而是图片中的漏洞条件：验证方接受攻击者提供的 `e'` 时，可以构造 `(r', s')` 使验签通过；如果验证方自己计算 `H(message)`，同一个签名就不能冒充真实消息签名。

核心构造对应如下代码：

```python
r_point = point_add(scalar_mult(u, G), scalar_mult(v, public_key))
r = r_point[0] % N_ORDER
s = (r * inverse_mod(v, N_ORDER)) % N_ORDER
forged_hash = (r * u * inverse_mod(v, N_ORDER)) % N_ORDER
```

## 实验结论

本次实验可以总结为：

1. 图中展示的是 ECDSA 的 existential forgery 场景：如果只验证攻击者给出的 hash，而不验证 hash 与真实消息的关系，攻击者可以构造 `(e', r', s')` 通过验签。
2. `bitcoin-core/secp256k1` 的 API 本身以 `msghash32` 为输入，因此上层必须负责消息哈希、上下文绑定和域分离。
3. Bitcoin 的正确修复方向是由共识代码根据交易上下文计算签名摘要，再调用 `libsecp256k1` 验证，而不是让外部输入决定待验证的 hash。
4. ECDSA 的 `(r, s)` / `(r, n-s)` 可延展性说明，签名验证不仅要“数学上有效”，还要有规范编码、lower-S 等协议规则。
5. Bitcoin Core 引入 `libsecp256k1` 既提升了共识安全性，也显著提高了 ECDSA 验证性能。
6. 性能提升来自专用有限域实现、固定基点预计算、wNAF、Shamir/Straus 多标量乘法、GLV endomorphism 和 Jacobian 坐标等数学与工程优化。

## 参考资料

- [bitcoin-core/secp256k1 GitHub 仓库](https://github.com/bitcoin-core/secp256k1)
- [libsecp256k1 README](https://github.com/bitcoin-core/secp256k1/blob/master/README.md)
- [libsecp256k1 ECDSA API 文档](https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h)
- [Bitcoin Core 0.12.0 Release Notes](https://bitcoincore.org/en/releases/0.12.0/)
- [Bitcoin Core PR #6954: use libsecp256k1 for ECDSA validation](https://github.com/bitcoin/bitcoin/pull/6954)
- [BIP66: Strict DER signatures](https://bips.dev/66/)
