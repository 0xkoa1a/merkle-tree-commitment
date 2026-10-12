# Merkle Tree Commitment

应用密码学作业一：先用一个短摘要固定一组消息，之后开封全部消息或其中一个位置，让别人核对内容与原承诺一致。实现使用手写 SHA3-256 和每叶子独立随机值，包含绑定性、隐藏性分析及性能评估。

## 先运行一个例子

需要 Python 3.9 或更新版本，无第三方运行时依赖。在仓库根目录执行 `PYTHONPATH=src python3 -B -m examples.demo`。

演示使用方案文档中的三个消息“6”“9”“0”，开封位置 2。你会看到承诺摘要、107 B 的证明，以及三个结果：有效开封为 True、篡改消息为 False、完整开封为 True。每次运行都会生成新的随机值，所以承诺摘要通常不同。

## 阅读与人工审查

- 先读 [方案设计](docs/方案设计.md)：从三个消息的小树理解承诺、认证路径、安全分析和 SHA3。
- 再读实现：`protocol.py` 定义字段和编码，`tree.py` 实现建树与开封，`sha3.py` 实现哈希。
- 对照 `tests/` 中的独立递归规格、固定编码样例和官方哈希答案，核对实现是否符合定义。
- 最后读 [性能报告](results/性能与验证结果.md)，了解实测结果和计时范围；[作业要求](docs/作业要求.md) 保留课程原文。

`commit(messages)` 返回公开承诺和承诺方的树状态；`tree.open(index)` 返回消息与证明；`verify()` 使用验证者此前保存的承诺检查消息和位置。完整开封使用 `tree.open_all()` 与 `verify_all()`。协议细节和安全假设集中在方案设计中。

## 测试与实验

以下命令都在仓库根目录执行：

- 正确性与安全回归：`PYTHONPATH=src python3 -B -m unittest discover -s tests -v`。
- 五组性能测量：`PYTHONPATH=src python3 -B -m benchmarks.benchmark --repetitions 5 --output-dir results-new`。

先执行测试，再测性能。基准会先核对单项和完整开封，再记录计时、证明大小、逻辑存储量、哈希次数和 Keccak 置换次数。输出目录保存 `results.json`；最终性能说明见 `results/性能与验证结果.md`。`-B` 用于避免生成 Python 缓存。

需要在其他程序中导入时，可在自己的虚拟环境运行 `python3 -m pip install -e .` 做可编辑安装。上面的源码运行命令不需要安装；打包工具可能需要获取 setuptools。

## 项目结构

| 路径 | 职责 |
| --- | --- |
| src/merkle_commitment/protocol.py | 承诺与开封的数据类型、字段校验及编解码 |
| src/merkle_commitment/tree.py | 建树、开封和验证 |
| src/merkle_commitment/sha3.py | SHA3-256 算法 |
| tests/ | 协议回归、独立规格、140 条 NIST 向量及 v1 编码样例 |
| examples/ | 基础开封演示 |
| benchmarks/ | 性能与哈希工作量采样 |
| docs/ | 方案设计、示意图和作业要求 |
| results/ | 原始样本和性能说明 |

实现代码构成 `merkle_commitment` 包，位于 `src/`；测试和辅助脚本单独组织。组员信息暂留空，提交前填写。合作修改使用独立分支和 Pull Request，协议或安全假设有变化时同步更新文档与测试。
