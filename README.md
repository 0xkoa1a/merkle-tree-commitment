# Merkle Tree Commitment

应用密码学作业一：先用一个短摘要固定一组消息，之后开封全部消息或其中一个位置，让别人核对内容与原承诺一致。实现使用手写 SHA3-256 和每叶子独立随机值，包含绑定性、隐藏性分析及性能评估。

## 先运行一个例子

需要 Python 3.9 或更新版本，无第三方运行时依赖。在仓库根目录执行 `PYTHONPATH=src python3 -B -m examples.demo`。

演示使用方案文档中的三个消息“6”“9”“0”，开封位置 2。你会看到承诺摘要、107 B 的证明，以及三个结果：有效开封为 True、篡改消息为 False、完整开封为 True。每次运行都会生成新的随机值，所以承诺摘要通常不同。

## 阅读与人工审查

- 先读 [方案设计](docs/方案设计.md)：从三个消息的小树理解承诺、认证路径、安全分析和 SHA3。
- 再读实现：`protocol.py` 定义字段和编码，`tree.py` 实现建树与开封，`sha3.py` 实现哈希。
- 对照 `correctness/` 中的独立递归规格、字节往返和官方哈希答案，核对实现是否符合定义。
- 最后读 [实验结果](results/实验结果.md)，了解分布诊断、缩微模型和开销曲线；[作业要求](docs/作业要求.md) 保留课程原文。

`commit(messages)` 返回公开承诺和承诺方的树状态；`tree.open(index)` 返回消息与证明；`verify()` 使用验证者此前保存的承诺检查消息和位置。完整开封使用 `tree.open_all()` 与 `verify_all()`。协议细节和安全假设集中在方案设计中。

## 测试与实验

以下命令都在仓库根目录执行：

- 基干正确性回归：`PYTHONPATH=src python3 -B -m unittest discover -s correctness -v`。
- 绘图库安装（只用于实验）：先运行 `python3 -m venv .venv`，再运行 `.venv/bin/python -m pip install '.[experiments]'`。
- 单叶 A/B/C/D 及树级 A′/B′/C′/D′：`PYTHONPATH=src .venv/bin/python -B experiments/distribution.py`。
- 性能实验 P1–P3：`PYTHONPATH=src .venv/bin/python -B experiments/performance.py`。

先执行四项基干测试，再依次运行两个实验脚本。性能采样期间不要并行运行其他实验。正式实验使用手写 Python SHA3，耗时可能达到数十分钟；输出包括 `results/distribution.json`、`results/performance.json` 和 `docs/assets/experiments/` 中的十一幅 SVG。性能结果保留九组原始计时，以中位数和四分位区间绘图；完整口径见方案设计。`-B` 用于避免生成 Python 缓存。

已有完整分布数据时，可添加 `--tree-only` 只补跑 B′/C′/D′，保留原样本并统一重绘。原 E 已改名 A′，数据和传播实验沿用。

仅检查脚本能否运行时，在脚本命令后加 `--quick --output-dir /tmp/mtc-smoke --figure-dir /tmp/mtc-smoke/figures`，避免用小样本覆盖正式结果。只重画已有数据时，分别添加 `--from-json results/distribution.json` 或 `--from-json results/performance.json`，不会重新采样。

每个实验类的 docstring 标明参数范围、缩小版运行方式和未来自写 C 后端可扩大的范围。C 后端和 multiproof 目前只有 TODO 接口说明，没有用系统哈希替换课程实现。

需要在其他程序中导入时，可在自己的虚拟环境运行 `python3 -m pip install -e .` 做可编辑安装。上面的源码运行命令不需要安装；打包工具可能需要获取 setuptools。

## 项目结构

| 路径 | 职责 |
| --- | --- |
| src/merkle_commitment/protocol.py | 承诺与开封的数据类型、字段校验及编解码 |
| src/merkle_commitment/tree.py | 建树、开封和验证 |
| src/merkle_commitment/sha3.py | SHA3-256 算法 |
| correctness/ | 四项基干回归：NIST、独立规格、代表性篡改和字节往返 |
| examples/ | 基础开封演示 |
| experiments/ | 四个单叶演示、四个树级实验、三个性能实验及绘图（两个脚本） |
| docs/ | 方案设计、示意图和作业要求 |
| results/ | 原始分布/计时样本和实验结果 |

实现代码构成 `merkle_commitment` 包，位于 `src/`；测试和辅助脚本单独组织。组员信息暂留空，提交前填写。合作修改使用独立分支和 Pull Request，协议或安全假设有变化时同步更新文档与测试。
