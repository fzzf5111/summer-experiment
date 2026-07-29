# 第一次实验：比特币测试网交易与完整区块解析

## 题目

在比特币测试网上发送一笔交易，并将该交易的数据解析到每一个比特（bit）；同时解析一个完整的区块，尝试编写脚本对其中的每一个字节（byte）进行计算和分析。

## 结论摘要

本实验围绕 Bitcoin 底层序列化格式完成两部分工作：

1. **测试网交易解析**：使用测试网交易 TXID 获取原始交易 hex，按 Bitcoin 交易序列化规则解析版本号、SegWit 标记、输入、输出、见证数据和锁定时间，并计算 `txid/wtxid`。
2. **完整区块解析**：获取测试网完整原始区块，解析 80 字节区块头、交易数量 VarInt，以及区块内每一笔交易；同时重新计算区块 hash、Merkle root、nBits 对应目标值并验证 PoW/Merkle 结果。

原脚本已进一步补充为 bit/byte 级解析脚本，修正了 Bitcoin 字段小端序、VarInt 小端序、SegWit marker/flag 与 witness 解析问题，并会导出 CSV 文件，逐行列出每个字节对应的 bit、所在字段和字段含义。

## 代码结构

```text
第一次实验/
├── README.md
├── 创新创业实践(1).docx
└── 创新创业实践1(1).py
```

`创新创业实践1(1).py` 只依赖 Python 标准库即可完成交易和区块解析；如需额外生成 testnet4 地址，可安装 `bitcoinlib` 后使用 `--new-address`。

运行后默认把分析结果写入：

```text
第一次实验/results/
├── transaction_fields.csv       交易字段：字节范围、bit 范围、原始 hex、解释
├── transaction_byte_bits.csv    交易每个字节的 8 个 bit 与所属字段
├── transaction_summary.json     交易 txid/wtxid、输入输出数量等摘要
├── block_fields.csv             完整区块字段：区块头、交易数量、区块内交易字段
├── block_byte_bits.csv          区块每个字节的 8 个 bit 与所属字段
└── block_summary.json           区块 hash、Merkle、PoW、交易数等摘要
```

## 运行方式

默认使用实验文档中的 testnet4 样例交易，并解析 testnet4 最新区块：

```bash
cd 第一次实验
python3 '创新创业实践1(1).py'
```

指定交易 TXID：

```bash
python3 '创新创业实践1(1).py' \
  --network testnet4 \
  --txid d02df80992768889a099ca96f03605ad5d5711c478dd38fce2948b91318d3975
```

如果已经保存了原始交易或原始区块，也可以离线解析：

```bash
python3 '创新创业实践1(1).py' \
  --tx-hex '<raw transaction hex>' \
  --block-hex '<raw block hex>'
```

若只想查看字段解析、不导出逐字节 bit 映射，可加：

```bash
python3 '创新创业实践1(1).py' --no-byte-map
```

## 交易序列化解析方法

Bitcoin 交易的基础结构如下：

```text
version              4 bytes, little-endian
[marker, flag]       SegWit 交易才存在，通常为 00 01
input_count          VarInt
inputs[]             每个输入包含 prev_txid、vout、scriptSig、sequence
output_count         VarInt
outputs[]            每个输出包含 value、scriptPubKey
witness[]            SegWit 交易才存在，每个输入对应一组 witness stack
locktime             4 bytes, little-endian
```

脚本通过 `read_varint()` 读取 Bitcoin CompactSize/VarInt：

```text
00..fc        直接表示数值，占 1 字节
fd + 2 bytes  后 2 字节小端序
fe + 4 bytes  后 4 字节小端序
ff + 8 bytes  后 8 字节小端序
```

解析时每个字段都会记录：

```text
字段名、起止字节、起止 bit、原始 hex、解释值、备注
```

例如一个 4 字节小端版本号字段 `02000000` 会被解释为：

```text
bytes 0-3
bits  0-31
raw   02000000
value 2
```

这比直接 `int('02000000', 16)` 更符合 Bitcoin 底层编码规则。

## SegWit 交易处理

实验文档中的样例交易包含 SegWit 标记，因此必须特殊处理：

```text
version | marker=00 | flag=01 | vin | vout | witness | locktime
```

如果不识别 `00 01`，会把 marker 误当成输入数量，导致“0 个输入”和金额异常。修正后的脚本会：

1. 在版本字段后识别 `marker=0x00, flag=0x01`；
2. 正确从 marker/flag 后继续读取输入数量；
3. 在输出后解析每个输入对应的 witness stack；
4. 计算 `txid` 时排除 marker、flag、witness；
5. 计算 `wtxid` 时使用完整交易字节。

## 输出脚本识别

脚本会对常见 `scriptPubKey` 做结构识别：

| 类型 | 字节模式 | 含义 |
|---|---|---|
| P2PKH | `76 a9 14 <20B> 88 ac` | 传统公钥哈希地址 |
| P2SH | `a9 14 <20B> 87` | 脚本哈希地址 |
| P2WPKH | `00 14 <20B>` | SegWit v0 公钥哈希 |
| P2WSH | `00 20 <32B>` | SegWit v0 脚本哈希 |
| P2TR | `51 20 <32B>` | Taproot v1 输出 |

未知脚本仍会保留完整 hex 与逐字节 bit 表，满足底层解析要求。

## 完整区块解析方法

Bitcoin 区块由区块头、交易数量和交易列表组成：

```text
block_header         80 bytes
transaction_count    VarInt
transactions[]       raw transaction serialization
```

其中 80 字节区块头字段为：

| 字节范围 | 字段 | 长度 | 编码 |
|---:|---|---:|---|
| 0-3 | version | 4 bytes | 小端序整数 |
| 4-35 | previous block hash | 32 bytes | 内部小端哈希，显示时反转 |
| 36-67 | merkle root | 32 bytes | 内部小端哈希，显示时反转 |
| 68-71 | timestamp | 4 bytes | 小端序 Unix 时间 |
| 72-75 | bits | 4 bytes | 小端序 compact target |
| 76-79 | nonce | 4 bytes | 小端序整数 |

脚本不仅解析区块头，还会继续解析 `transaction_count` 和区块内所有交易，因此属于完整区块解析，而不是只解析区块头。

## 计算与验证

脚本对解析结果做如下计算：

```text
txid   = double_sha256(non_witness_serialization) reversed
wtxid  = double_sha256(full_transaction_serialization) reversed
block_hash = double_sha256(block_header) reversed
merkle_root = pairwise double_sha256(txid_internal_bytes)
target = compact_bits_to_target(nBits)
pow_valid = int(block_header_hash) <= target
```

Merkle root 计算时，如果某层交易哈希数量为奇数，复制最后一个哈希再两两合并，与 Bitcoin 共识规则一致。

## bit/byte 级产物说明

`transaction_byte_bits.csv` 与 `block_byte_bits.csv` 的每一行对应原始数据中的一个字节：

```text
byte_index, bit_range, hex, bits_b7_to_b0, field
0, 0-7, 02, 00000010, tx.version
1, 8-15, 00, 00000000, tx.version
...
```

因此可以从 CSV 直接定位任意一个 bit 属于哪个字段。例如第 `i` 个字节对应 bit 范围为：

```text
8*i  ~  8*i+7
```

这满足“交易解析到每一个 bit”和“区块逐字节计算分析”的要求。

## 实验结论

本实验完成了 Bitcoin testnet 交易和完整区块的底层解析。脚本可以从 TXID/区块 hash 获取原始数据，也可以离线解析已保存的 hex；解析结果覆盖小端整数、VarInt、输入/输出脚本、SegWit witness、区块头、区块交易列表、Merkle root 与 PoW 校验。字段 CSV 与逐字节 bit CSV 可以逐项核对每个 bit/byte 的归属和含义，满足第一次作业要求。
