#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
第一次实验：比特币测试网交易与完整区块解析。

功能：
1. 从 mempool.space testnet/testnet4 API 获取原始交易 hex 与原始区块；
2. 正确处理 Bitcoin 小端字段、VarInt、SegWit marker/flag 与 witness；
3. 将交易字段解析到 bit 范围，并导出逐字节/逐 bit 映射 CSV；
4. 解析完整区块：80 字节区块头、交易数量、区块内每笔交易；
5. 计算 txid/wtxid、区块 hash、Merkle root、nBits 目标值和 PoW 校验结果。

运行示例：
    python3 "创新创业实践1(1).py" --txid d02df80992768889a099ca96f03605ad5d5711c478dd38fce2948b91318d3975
    python3 "创新创业实践1(1).py" --network testnet4 --latest-block
    python3 "创新创业实践1(1).py" --tx-hex <raw_tx_hex> --block-hex <raw_block_hex>
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


DEFAULT_TESTNET4_TXID = "d02df80992768889a099ca96f03605ad5d5711c478dd38fce2948b91318d3975"
API_BASES = {
    "testnet4": "https://mempool.space/testnet4/api",
    "testnet3": "https://mempool.space/testnet/api",
    "mainnet": "https://mempool.space/api",
}


@dataclass
class Field:
    """一个已经解析出的连续字节字段。end 为开区间。"""

    name: str
    start: int
    end: int
    raw_hex: str
    value: str = ""
    note: str = ""

    @property
    def byte_range(self) -> str:
        if self.end <= self.start:
            return "empty"
        return f"{self.start}-{self.end - 1}"

    @property
    def bit_range(self) -> str:
        if self.end <= self.start:
            return "empty"
        return f"{self.start * 8}-{self.end * 8 - 1}"


@dataclass
class ParsedTransaction:
    start: int
    end: int
    txid: str
    wtxid: str
    version: int
    is_segwit: bool
    input_count: int
    output_count: int
    locktime: int
    fields: list[Field]

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class ParsedBlock:
    block_hash: str
    version: int
    prev_block_hash: str
    merkle_root: str
    merkle_root_calculated: str
    timestamp: int
    bits: int
    target_hex: str
    nonce: int
    tx_count: int
    pow_valid: bool
    merkle_valid: bool
    parsed_size: int
    fields: list[Field]
    transactions: list[ParsedTransaction]


# ----------------------------- 基础编码/解码工具 -----------------------------


def clean_hex(hex_text: str) -> str:
    """移除空白并校验十六进制字符串。"""
    h = "".join(hex_text.strip().split()).lower()
    if h.startswith("0x"):
        h = h[2:]
    if len(h) % 2 != 0:
        raise ValueError("hex 字符串长度必须为偶数")
    try:
        bytes.fromhex(h)
    except ValueError as exc:
        raise ValueError("输入不是合法十六进制字符串") from exc
    return h


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def u32_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def u64_le(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def bits_of(data: bytes) -> str:
    return " ".join(f"{b:08b}" for b in data)


def short_hex(raw_hex: str, limit: int = 96) -> str:
    if len(raw_hex) <= limit:
        return raw_hex
    return raw_hex[: limit // 2] + "..." + raw_hex[-limit // 2 :]


def add_field(fields: list[Field], data: bytes, name: str, start: int, end: int, value: object = "", note: str = "") -> None:
    fields.append(Field(name=name, start=start, end=end, raw_hex=data[start:end].hex(), value=str(value), note=note))


def read_varint(data: bytes, offset: int) -> tuple[int, int, int]:
    """读取 Bitcoin CompactSize/VarInt，返回 (value, consumed_bytes, new_offset)。"""
    if offset >= len(data):
        raise ValueError(f"offset {offset} 超出数据长度")
    first = data[offset]
    if first < 0xFD:
        return first, 1, offset + 1
    if first == 0xFD:
        if offset + 3 > len(data):
            raise ValueError("VarInt 0xfd 长度不足")
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), 3, offset + 3
    if first == 0xFE:
        if offset + 5 > len(data):
            raise ValueError("VarInt 0xfe 长度不足")
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), 5, offset + 5
    if offset + 9 > len(data):
        raise ValueError("VarInt 0xff 长度不足")
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), 9, offset + 9


def describe_script(script: bytes) -> str:
    """识别常见 ScriptPubKey 类型，便于实验报告说明字段含义。"""
    h = script.hex()
    if len(script) == 25 and script[:3].hex() == "76a914" and script[-2:].hex() == "88ac":
        return "P2PKH: OP_DUP OP_HASH160 <20-byte pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG"
    if len(script) == 23 and script[:2].hex() == "a914" and script[-1] == 0x87:
        return "P2SH: OP_HASH160 <20-byte scriptHash> OP_EQUAL"
    if len(script) == 22 and script[:2].hex() == "0014":
        return "P2WPKH: witness v0 <20-byte pubKeyHash>"
    if len(script) == 34 and script[:2].hex() == "0020":
        return "P2WSH: witness v0 <32-byte scriptHash>"
    if len(script) == 34 and script[:2].hex() == "5120":
        return "P2TR: witness v1 <32-byte x-only pubkey>"
    if len(script) == 0:
        return "empty script"
    return "custom/unknown script"


# ----------------------------- 交易解析 -----------------------------


def parse_transaction(data: bytes, offset: int = 0, prefix: str = "tx") -> ParsedTransaction:
    """从 data[offset:] 解析一笔交易，支持 legacy 与 SegWit。"""
    start = offset
    fields: list[Field] = []

    if offset + 4 > len(data):
        raise ValueError("交易版本字段长度不足")
    version_start = offset
    version = u32_le(data, offset)
    add_field(fields, data, f"{prefix}.version", version_start, version_start + 4, version, "4 字节小端序")
    offset += 4

    marker_flag_start: Optional[int] = None
    is_segwit = False
    if offset + 2 <= len(data) and data[offset] == 0x00 and data[offset + 1] != 0x00:
        marker_flag_start = offset
        add_field(fields, data, f"{prefix}.segwit_marker", offset, offset + 1, data[offset], "SegWit marker 必须为 0x00")
        add_field(fields, data, f"{prefix}.segwit_flag", offset + 1, offset + 2, data[offset + 1], "SegWit flag 通常为 0x01")
        offset += 2
        is_segwit = True

    body_start = offset
    count_start = offset
    input_count, consumed, offset = read_varint(data, offset)
    add_field(fields, data, f"{prefix}.input_count", count_start, count_start + consumed, input_count, "VarInt")

    for i in range(input_count):
        p = f"{prefix}.vin[{i}]"
        prev_start = offset
        if offset + 36 > len(data):
            raise ValueError(f"输入 {i} 长度不足")
        prev_txid = data[offset : offset + 32][::-1].hex()
        add_field(fields, data, f"{p}.prev_txid", prev_start, prev_start + 32, prev_txid, "原始字节为小端序，显示时反转")
        offset += 32

        vout_start = offset
        vout = u32_le(data, offset)
        add_field(fields, data, f"{p}.prev_vout", vout_start, vout_start + 4, vout, "4 字节小端序")
        offset += 4

        script_len_start = offset
        script_len, consumed, offset = read_varint(data, offset)
        add_field(fields, data, f"{p}.scriptSig_len", script_len_start, script_len_start + consumed, script_len, "VarInt")

        script_start = offset
        if offset + script_len > len(data):
            raise ValueError(f"输入 {i} scriptSig 长度不足")
        script_sig = data[offset : offset + script_len]
        add_field(fields, data, f"{p}.scriptSig", script_start, script_start + script_len, f"{script_len} bytes", describe_script(script_sig))
        offset += script_len

        seq_start = offset
        if offset + 4 > len(data):
            raise ValueError(f"输入 {i} sequence 长度不足")
        sequence = u32_le(data, offset)
        add_field(fields, data, f"{p}.sequence", seq_start, seq_start + 4, sequence, "0xffffffff 表示默认最终序列")
        offset += 4

    output_count_start = offset
    output_count, consumed, offset = read_varint(data, offset)
    add_field(fields, data, f"{prefix}.output_count", output_count_start, output_count_start + consumed, output_count, "VarInt")

    for i in range(output_count):
        p = f"{prefix}.vout[{i}]"
        value_start = offset
        if offset + 8 > len(data):
            raise ValueError(f"输出 {i} value 长度不足")
        sats = u64_le(data, offset)
        add_field(fields, data, f"{p}.value", value_start, value_start + 8, f"{sats} sats = {sats / 100_000_000:.8f} BTC", "8 字节小端序")
        offset += 8

        script_len_start = offset
        script_len, consumed, offset = read_varint(data, offset)
        add_field(fields, data, f"{p}.scriptPubKey_len", script_len_start, script_len_start + consumed, script_len, "VarInt")

        script_start = offset
        if offset + script_len > len(data):
            raise ValueError(f"输出 {i} scriptPubKey 长度不足")
        script_pubkey = data[offset : offset + script_len]
        add_field(fields, data, f"{p}.scriptPubKey", script_start, script_start + script_len, f"{script_len} bytes", describe_script(script_pubkey))
        offset += script_len

    witness_start = offset
    if is_segwit:
        for i in range(input_count):
            p = f"{prefix}.witness[{i}]"
            stack_count_start = offset
            item_count, consumed, offset = read_varint(data, offset)
            add_field(fields, data, f"{p}.stack_item_count", stack_count_start, stack_count_start + consumed, item_count, "VarInt")
            for j in range(item_count):
                item_len_start = offset
                item_len, consumed, offset = read_varint(data, offset)
                add_field(fields, data, f"{p}.item[{j}].len", item_len_start, item_len_start + consumed, item_len, "VarInt")
                item_start = offset
                if offset + item_len > len(data):
                    raise ValueError(f"witness {i}.{j} 长度不足")
                add_field(fields, data, f"{p}.item[{j}].data", item_start, item_start + item_len, f"{item_len} bytes", "签名、公钥或脚本见证数据")
                offset += item_len
    witness_end = offset

    locktime_start = offset
    if offset + 4 > len(data):
        raise ValueError("locktime 长度不足")
    locktime = u32_le(data, offset)
    add_field(fields, data, f"{prefix}.locktime", locktime_start, locktime_start + 4, locktime, "0 表示立即有效；非零可表示区块高度或 Unix 时间")
    offset += 4

    raw_tx = data[start:offset]
    if is_segwit:
        assert marker_flag_start is not None
        non_witness = data[start : start + 4] + data[body_start:witness_start] + data[locktime_start:offset]
    else:
        non_witness = raw_tx
    txid = dsha256(non_witness)[::-1].hex()
    wtxid = dsha256(raw_tx)[::-1].hex() if is_segwit else txid

    return ParsedTransaction(
        start=start,
        end=offset,
        txid=txid,
        wtxid=wtxid,
        version=version,
        is_segwit=is_segwit,
        input_count=input_count,
        output_count=output_count,
        locktime=locktime,
        fields=fields,
    )


# ----------------------------- 区块解析 -----------------------------


def compact_bits_to_target(bits_value: int) -> int:
    exponent = bits_value >> 24
    mantissa = bits_value & 0x007FFFFF if bits_value & 0x00800000 else bits_value & 0x00FFFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def merkle_root_from_txids(txids: Iterable[str]) -> str:
    layer = [bytes.fromhex(txid)[::-1] for txid in txids]
    if not layer:
        return ""
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [dsha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0][::-1].hex()


def parse_block(data: bytes) -> ParsedBlock:
    if len(data) < 81:
        raise ValueError("完整区块至少应包含 80 字节区块头和交易数量 VarInt")

    fields: list[Field] = []
    header = data[:80]

    version = u32_le(data, 0)
    add_field(fields, data, "block.header.version", 0, 4, version, "4 字节小端序")

    prev_hash = data[4:36][::-1].hex()
    add_field(fields, data, "block.header.prev_block_hash", 4, 36, prev_hash, "32 字节小端序哈希，显示时反转")

    merkle_root = data[36:68][::-1].hex()
    add_field(fields, data, "block.header.merkle_root", 36, 68, merkle_root, "32 字节小端序 Merkle root，显示时反转")

    timestamp = u32_le(data, 68)
    timestamp_text = datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    add_field(fields, data, "block.header.timestamp", 68, 72, f"{timestamp} ({timestamp_text})", "4 字节小端序 Unix 时间")

    bits = u32_le(data, 72)
    target = compact_bits_to_target(bits)
    add_field(fields, data, "block.header.bits", 72, 76, f"{bits} / target={target:064x}", "nBits 压缩难度目标，4 字节小端序")

    nonce = u32_le(data, 76)
    add_field(fields, data, "block.header.nonce", 76, 80, nonce, "4 字节小端序")

    block_hash = dsha256(header)[::-1].hex()
    pow_valid = int.from_bytes(dsha256(header), "little") <= target

    offset = 80
    tx_count_start = offset
    tx_count, consumed, offset = read_varint(data, offset)
    add_field(fields, data, "block.tx_count", tx_count_start, tx_count_start + consumed, tx_count, "VarInt")

    transactions: list[ParsedTransaction] = []
    for i in range(tx_count):
        tx = parse_transaction(data, offset, prefix=f"block.tx[{i}]")
        transactions.append(tx)
        fields.extend(tx.fields)
        offset = tx.end

    merkle_calculated = merkle_root_from_txids(tx.txid for tx in transactions)
    merkle_valid = merkle_calculated == merkle_root

    return ParsedBlock(
        block_hash=block_hash,
        version=version,
        prev_block_hash=prev_hash,
        merkle_root=merkle_root,
        merkle_root_calculated=merkle_calculated,
        timestamp=timestamp,
        bits=bits,
        target_hex=f"{target:064x}",
        nonce=nonce,
        tx_count=tx_count,
        pow_valid=pow_valid,
        merkle_valid=merkle_valid,
        parsed_size=offset,
        fields=fields,
        transactions=transactions,
    )


# ----------------------------- 输出报告 -----------------------------


def build_field_lookup(length: int, fields: list[Field]) -> list[str]:
    """为每个字节预先建立字段名索引，避免完整区块导出时反复扫描字段表。"""
    lookup = [""] * length
    for field in fields:
        start = max(0, field.start)
        end = min(length, field.end)
        for i in range(start, end):
            lookup[i] = field.name if not lookup[i] else lookup[i] + ";" + field.name
    return lookup


def write_byte_bit_csv(path: Path, data: bytes, fields: list[Field]) -> None:
    """导出每个字节的 bit 表，满足“解析到每一个 bit/byte”的可检查产物。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    byte_to_field = build_field_lookup(len(data), fields)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["byte_index", "bit_range", "hex", "bits_b7_to_b0", "field"])
        for i, b in enumerate(data):
            writer.writerow([i, f"{i * 8}-{i * 8 + 7}", f"{b:02x}", f"{b:08b}", byte_to_field[i]])


def write_fields_csv(path: Path, fields: list[Field]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["field", "byte_range", "bit_range", "raw_hex", "value", "note"])
        for field in fields:
            writer.writerow([field.name, field.byte_range, field.bit_range, field.raw_hex, field.value, field.note])


def print_transaction(tx: ParsedTransaction, data: bytes, max_fields: int = 80) -> None:
    print("\n" + "=" * 72)
    print("交易 Transaction 解析结果")
    print("=" * 72)
    print(f"txid   : {tx.txid}")
    print(f"wtxid  : {tx.wtxid}")
    print(f"size   : {tx.size} bytes")
    print(f"version: {tx.version}")
    print(f"segwit : {tx.is_segwit}")
    print(f"inputs : {tx.input_count}")
    print(f"outputs: {tx.output_count}")
    print(f"locktime: {tx.locktime}")
    print("-" * 72)
    for n, field in enumerate(tx.fields[:max_fields], 1):
        raw = data[field.start : field.end]
        print(f"[{n:02d}] {field.name}")
        print(f"     bytes {field.byte_range}, bits {field.bit_range}")
        print(f"     raw  : {short_hex(field.raw_hex)}")
        print(f"     bits : {short_hex(bits_of(raw), 128)}")
        print(f"     value: {field.value}")
        if field.note:
            print(f"     note : {field.note}")
    if len(tx.fields) > max_fields:
        print(f"... 还有 {len(tx.fields) - max_fields} 个字段已写入 CSV。")
    print("=" * 72)


def print_block(block: ParsedBlock, max_txs: int = 20, max_fields: int = 90) -> None:
    print("\n" + "=" * 72)
    print("完整区块 Block 解析结果")
    print("=" * 72)
    print(f"block hash          : {block.block_hash}")
    print(f"version             : {block.version}")
    print(f"previous block hash : {block.prev_block_hash}")
    print(f"merkle root(header) : {block.merkle_root}")
    print(f"merkle root(calc)   : {block.merkle_root_calculated}")
    print(f"merkle valid        : {block.merkle_valid}")
    print(f"timestamp UTC       : {datetime.fromtimestamp(block.timestamp, timezone.utc).isoformat()}")
    print(f"bits                : {block.bits}")
    print(f"target              : {block.target_hex}")
    print(f"nonce               : {block.nonce}")
    print(f"proof-of-work valid : {block.pow_valid}")
    print(f"tx count            : {block.tx_count}")
    print(f"parsed size         : {block.parsed_size} bytes")
    print("-" * 72)
    print("区块内交易摘要：")
    for i, tx in enumerate(block.transactions[:max_txs]):
        print(f"  tx[{i}] offset={tx.start}, size={tx.size}, inputs={tx.input_count}, outputs={tx.output_count}, segwit={tx.is_segwit}, txid={tx.txid}")
    if block.tx_count > max_txs:
        print(f"  ... 还有 {block.tx_count - max_txs} 笔交易，完整字段已写入 CSV。")
    print("-" * 72)
    print("前若干字段：")
    for n, field in enumerate(block.fields[:max_fields], 1):
        print(f"[{n:02d}] {field.name}: bytes {field.byte_range}, bits {field.bit_range}, value={field.value}")
    if len(block.fields) > max_fields:
        print(f"... 还有 {len(block.fields) - max_fields} 个字段已写入 CSV。")
    print("=" * 72)


# ----------------------------- 网络获取 -----------------------------


def http_get_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 bitcoin-parser-experiment"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8").strip()


def http_get_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 bitcoin-parser-experiment"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def api_base(network: str) -> str:
    if network not in API_BASES:
        raise ValueError(f"未知网络 {network}，可选：{', '.join(API_BASES)}")
    return API_BASES[network]


def fetch_tx_hex(txid: str, network: str) -> str:
    return http_get_text(f"{api_base(network)}/tx/{txid}/hex")


def fetch_block_hash(args: argparse.Namespace) -> str:
    if args.block_hash:
        return args.block_hash
    if args.block_height is not None:
        return http_get_text(f"{api_base(args.network)}/block-height/{args.block_height}")
    return http_get_text(f"{api_base(args.network)}/blocks/tip/hash")


def fetch_block_raw(block_hash: str, network: str) -> bytes:
    return http_get_bytes(f"{api_base(network)}/block/{block_hash}/raw")


# ----------------------------- 可选：生成测试网地址 -----------------------------


def maybe_generate_testnet_address() -> None:
    """可选功能：若本机安装 bitcoinlib，可生成一个测试网地址用于水龙头收币。"""
    try:
        from bitcoinlib.keys import Key  # type: ignore
    except Exception:
        print("未安装 bitcoinlib，跳过地址生成。若需要：pip install bitcoinlib")
        return
    key = Key(network="testnet4")
    print("\n生成的 Bitcoin testnet4 地址（用于水龙头收测试币）：")
    print(f"address: {key.address()}")
    print(f"WIF    : {key.wif()}")


# ----------------------------- 主程序 -----------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="比特币测试网交易与完整区块 bit/byte 级解析脚本")
    parser.add_argument("--network", choices=sorted(API_BASES), default="testnet4", help="mempool.space 网络，默认 testnet4")
    parser.add_argument("--txid", default=DEFAULT_TESTNET4_TXID, help="要解析的交易 ID；默认使用实验文档中的 testnet4 样例交易")
    parser.add_argument("--tx-hex", help="直接提供原始交易 hex；提供后不会联网获取交易")
    parser.add_argument("--block-hash", help="要解析的区块 hash；默认解析最新区块")
    parser.add_argument("--block-height", type=int, help="按高度解析区块；优先级低于 --block-hash")
    parser.add_argument("--block-hex", help="直接提供完整原始区块 hex；提供后不会联网获取区块")
    parser.add_argument("--latest-block", action="store_true", help="显式解析最新区块；不传 --block-hash/--block-height 时默认也是最新区块")
    parser.add_argument("--out-dir", default="第一次实验/results", help="CSV/JSON 输出目录")
    parser.add_argument("--no-byte-map", action="store_true", help="只导出字段 CSV，不导出逐字节 bit 映射 CSV")
    parser.add_argument("--new-address", action="store_true", help="可选：生成一个 testnet4 地址用于接收水龙头测试币")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.new_address:
        maybe_generate_testnet_address()

    # 1. 交易解析
    try:
        if args.tx_hex:
            tx_hex = clean_hex(args.tx_hex)
            tx_source = "--tx-hex"
        else:
            tx_source = args.txid
            print(f"正在从 {args.network} 获取交易 hex: {args.txid}")
            tx_hex = clean_hex(fetch_tx_hex(args.txid, args.network))
        tx_data = bytes.fromhex(tx_hex)
        tx = parse_transaction(tx_data, 0, prefix="tx")
        if tx.end != len(tx_data):
            print(f"提示：交易解析后还剩 {len(tx_data) - tx.end} bytes 未消费，请检查输入。")
        print_transaction(tx, tx_data)
        write_fields_csv(out_dir / "transaction_fields.csv", tx.fields)
        if not args.no_byte_map:
            write_byte_bit_csv(out_dir / "transaction_byte_bits.csv", tx_data, tx.fields)
        (out_dir / "transaction_summary.json").write_text(
            json.dumps(
                {
                    "source": tx_source,
                    "txid": tx.txid,
                    "wtxid": tx.wtxid,
                    "size": tx.size,
                    "version": tx.version,
                    "segwit": tx.is_segwit,
                    "input_count": tx.input_count,
                    "output_count": tx.output_count,
                    "locktime": tx.locktime,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"交易解析失败：{exc}", file=sys.stderr)
        return 1

    # 2. 完整区块解析
    try:
        if args.block_hex:
            block_source = "--block-hex"
            block_data = bytes.fromhex(clean_hex(args.block_hex))
        else:
            block_hash = fetch_block_hash(args)
            block_source = block_hash
            print(f"\n正在从 {args.network} 获取完整原始区块: {block_hash}")
            block_data = fetch_block_raw(block_hash, args.network)
        block = parse_block(block_data)
        if block.parsed_size != len(block_data):
            print(f"提示：区块解析后还剩 {len(block_data) - block.parsed_size} bytes 未消费，请检查输入。")
        print_block(block)
        write_fields_csv(out_dir / "block_fields.csv", block.fields)
        if not args.no_byte_map:
            write_byte_bit_csv(out_dir / "block_byte_bits.csv", block_data, block.fields)
        (out_dir / "block_summary.json").write_text(
            json.dumps(
                {
                    "source": block_source,
                    "block_hash": block.block_hash,
                    "version": block.version,
                    "prev_block_hash": block.prev_block_hash,
                    "merkle_root_header": block.merkle_root,
                    "merkle_root_calculated": block.merkle_root_calculated,
                    "merkle_valid": block.merkle_valid,
                    "timestamp": block.timestamp,
                    "bits": block.bits,
                    "target_hex": block.target_hex,
                    "nonce": block.nonce,
                    "pow_valid": block.pow_valid,
                    "tx_count": block.tx_count,
                    "parsed_size": block.parsed_size,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"区块解析失败：{exc}", file=sys.stderr)
        return 1

    print("\n输出文件：")
    for p in sorted(out_dir.glob("*")):
        print(f"  {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
