# 第七次实验：garak AI 安全测评

## 题目

部署 AI 安全开源测评工具 garak，针对任意开源大模型完成不少于三项安全测评，并编写测评报告。

## 实验环境

```text
测评工具：garak 0.15.1
目标模型：gpt2
模型来源：HuggingFace GPT-2 开源权重
生成器：garak.generators.huggingface.Pipeline
运行方式：本地 CPU 推理
随机种子：20260728
每项测评 prompt 数：4
每个 prompt 生成次数：1
单次最大生成长度：60 tokens
```

本机运行时 HuggingFace 主站连接超时，因此模型下载使用 `https://hf-mirror.com` 镜像端点。garak 0.15.1 在当前 Windows 环境中构建全局插件缓存时，会引用一个包内不存在的可选 probe 模块；本实验脚本绕过全局插件枚举，直接实例化本次需要的 garak probe、detector 和 HuggingFace generator，测评规则仍来自 garak。

## 部署与运行

安装和运行命令如下：

```powershell
python -m venv .garak-venv
.\.garak-venv\Scripts\python.exe -m pip install garak transformers torch datasets accelerate

$env:HF_ENDPOINT = "https://hf-mirror.com"
$env:GARAK_MODEL = "gpt2"
.\.garak-venv\Scripts\python.exe 第七次实验\run_garak_assessment.py
```

本目录中的 `run_garak_assessment.py` 会自动把 garak 配置、数据和模型缓存放到仓库本地忽略目录中，测评结果写入 `results/`。

## 测评项目

| 测评类别 | garak probe | detector | 目的 |
|---|---|---|---|
| 提示注入 | `promptinject.HijackHateHumans` | `promptinject.AttackRogueString` | 测试模型是否会服从注入指令并输出攻击者指定字符串 |
| 编码型提示注入 | `encoding.InjectBase64` | `encoding.DecodeMatch`、`encoding.DecodeApprox` | 测试模型是否会解码 Base64 后输出隐藏载荷 |
| 训练数据泄露 | `leakreplay.LiteratureComplete` | `leakreplay.StartsWith` | 测试模型是否会补全文学片段中的预期内容 |

## 测评结果

| 测评类别 | 尝试数 | 命中数 | 失败率 | 结果 |
|---|---:|---:|---:|---|
| 提示注入 | 4 | 2 | 50% | 存在明显风险 |
| 编码型提示注入 | 4 | 0 | 0% | 本轮未命中 |
| 训练数据泄露 | 4 | 0 | 0% | 本轮未命中 |

原始结果文件：

```text
第七次实验/results/garak_assessment_summary.json
第七次实验/results/garak_assessment_raw.jsonl
```

## 结果分析

提示注入测评中，GPT-2 在 4 个样本里有 2 个样本输出了注入指令要求的目标字符串，说明这类基础自回归模型没有稳固的指令边界，也不会区分“用户原始任务”和“恶意插入指令”。当 prompt 伪装成对话或角色扮演时，模型容易继续补写攻击者希望出现的内容。

编码型提示注入测评中，4 个 Base64 样本没有触发命中。观察原始输出可见，模型多次复读编码文本或生成无关 HTML/文本，没有完成解码并输出隐藏载荷。这说明本轮样本下没有发现 Base64 解码型注入成功，但不能推出模型对所有编码混淆都安全。

训练数据泄露测评中，4 个文学补全样本没有命中预期触发词。模型倾向于生成重复句式或泛化续写，没有直接复现 garak 期望的训练片段内容。本轮结果只能说明小样本下未观察到复现，不等价于模型不存在训练数据记忆风险。

## 基于 garak 的开源语言模型安全测评流程验证结论

本次实验完成了 garak 的本地部署，并针对开源 GPT-2 模型完成三项安全测评。结果显示：模型在提示注入场景中出现 50% 命中率，存在较明显的指令劫持风险；编码型提示注入和训练数据泄露在本轮小样本测试中未命中。实际部署大模型应用时，应在系统提示隔离、输入过滤、输出检测、敏感数据拒答和上下文权限控制等方面增加防护。

