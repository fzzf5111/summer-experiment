# 暑期实验课实验汇总

组员：张宇森、王圣恺、徐啸辰、孙翌航

本仓库保存暑期实验课第一次到第七次实验的代码实现和实验报告。每个实验目录中的 `README.md` 或 `readme.md` 为对应实验报告，代码文件用于复现实验结果。

## 目录

```text
.
├── 第一次实验/  Bitcoin testnet 交易 bit 级解析与完整区块 byte 级解析
├── 第二次实验/  ECDSA hash 绑定问题分析与伪造演示
├── 第三次实验/  SM4 对称密码软件实现与优化
├── 第四次实验/  SM3 SIMD 与通用寄存器混合优化
├── 第五次实验/  Microsoft SEAL/BFV 密文卷积
├── 第六次实验/  密文卷积旋转次数最小性分析
└── 第七次实验/  garak AI 安全测评
```

## 作业要求对应关系

| 课程作业 | 要求摘要 | 仓库实现 | 符合情况 |
|---|---|---|---|
| 作业1 | 在 Bitcoin 测试网发送/获取交易，交易解析到 bit；解析完整区块并逐 byte 分析 | `第一次实验/创新创业实践1(1).py` 解析 testnet4 交易、SegWit witness、完整 raw block、Merkle root、PoW，并导出 bit/byte CSV | 已补齐 |
| 作业2 | 分析 bitcoin-core/secp256k1 中 Bitcoin ECDSA 漏洞修复、性能改进和数学原理 | `第二次实验/README.md` 与 `ecdsa_hash_forgery_demo.py` | 符合 |
| 作业3 | 对称密码软件实现，覆盖 T-table、shuffle、最新指令集中的两种方法，并实现 CTR/GCM/XTS | `第三次实验/` 实现 SM4 基础/T-table/shuffle/x86/ARM 路径及 CTR/GCM/XTS | 符合 |
| 作业4 | SM3 软件实现与优化，使用 SIMD 和通用寄存器混合，实现 ARM64 与 x86 两种架构指令集 | `第四次实验/` 实现 SM3 标量、multi-buffer SIMD、x86 AVX2/AVX512、ARM64 NEON 路径 | 符合 |
| 作业5 | 选择开源 FHE 库，实现 `4x4` 输入、`3x3` 卷积核密文卷积并验证 | `第五次实验/` 使用 Microsoft SEAL BFV batching 完成密文卷积 | 符合 |
| 作业6 | 探索“打包→旋转→累加”卷积旋转次数是否达到理论最小值 | `第六次实验/rotation_minimum_analysis.py` 与第五次实验 SEAL 程序共同验证 8 次/4 次最小性 | 符合 |
| 作业7 | 部署 garak，对开源大模型完成不少于三项安全测评并写报告 | `第七次实验/` 对 GPT-2 完成提示注入、Base64 注入、训练数据泄露测评 | 符合 |

## 实验说明

第一次实验实现 Bitcoin 原始交易和完整原始区块解析。脚本支持 testnet4/testnet3/mainnet 的 mempool.space API，也支持离线传入 raw hex；输出字段级 CSV 和逐字节 bit CSV，用于核对每一个 bit/byte 的含义。

第二次实验分析 ECDSA 验证只绑定外部 hash 而不绑定真实消息时的伪造问题，并说明 Bitcoin 共识代码应自行计算交易签名摘要后再调用 `libsecp256k1` 验签。

第三次实验实现 SM4 基础加解密，并覆盖 T-table、shuffle S-box、x86 PCLMUL/AVX2、ARM64 NEON/SM4E/PMULL 等优化路径，同时实现 CTR、GCM、XTS 工作模式的软件优化模型。

第四次实验实现 SM3 标量基准和 multi-buffer SIMD 模型，覆盖 x86 AVX2、x86 AVX512、ARM64 NEON 两类架构路径，说明 SIMD 寄存器和通用寄存器的分工。

第五次实验使用开源全同态加密库 Microsoft SEAL 4.1.2，基于 BFV batching 对 `4x4` 输入和 `3x3` 卷积核实现密文卷积，解密结果与明文卷积一致。

第六次实验基于“打包、旋转、累加”策略，对直接行主序打包和 im2col 打包分别统计旋转次数，并验证 im2col 的 4 次旋转达到 `ceil(log2(9))` 理论最小值。

第七次实验部署 garak 0.15.1，针对开源 GPT-2 模型完成提示注入、Base64 编码型提示注入、训练数据泄露三项测评，并保存原始测评结果和报告。

## 运行方式

```bash
python3 '第一次实验/创新创业实践1(1).py' --network testnet4 --no-byte-map

python3 第二次实验/ecdsa_hash_forgery_demo.py

python3 第三次实验/sm4_modes_optimization_demo.py
make -C 第三次实验 test

python3 第四次实验/sm3_simd_hybrid_demo.py
make -C 第四次实验 test
make -C 第四次实验 sm3_x86_avx512

make -C 第五次实验 run
python3 第六次实验/rotation_minimum_analysis.py
python 第七次实验/run_garak_assessment.py
```

第五次实验依赖 Microsoft SEAL。本机已将 SEAL 安装到仓库本地 `.local` 目录；该目录为本地依赖，不提交到 GitHub。重新克隆仓库后，可按第五次实验报告中的说明安装 SEAL，再运行 `make -C 第五次实验 run`。

第七次实验依赖 garak、transformers 和 torch。本机使用仓库本地 `.garak-venv` 与 `.hf-cache` 运行测评，这些目录为本地依赖和模型缓存，不提交到 GitHub。
