# Merkle Tree Commitment

应用密码学作业一：用手写 SHA3-256 实现随机化 Merkle 向量承诺，支持完整开封和单项开封，包含 binding/hiding 分析及性能评估。

## 项目结构

| 路径 | 职责 |
| --- | --- |
| src/merkle_commitment/sha3.py | SHA3-256 算法 |
| src/merkle_commitment/protocol.py | 承诺、证明、完整开封的数据类型及严格编解码 |
| src/merkle_commitment/tree.py | 建树、开封和验证 |
| tests/ | 协议回归、独立规格、140 条 NIST 向量及 v1 编码固定样例 |
| examples/ | 基础演示及低熵猜测实验 |
| benchmarks/ | 性能采样和结果表格生成 |
| docs/ | 作业要求及方案设计 |
| results/ | 测量原始样本、执行日志及性能表格 |

`src` 是源码根目录，`merkle_commitment` 是实际导入包；该组织遵循 [PyPA 的 src 布局说明](https://packaging.python.org/en/latest/discussions/src-layout-vs-flat-layout/)。测试、文档和基准不被打包为库代码。

## 运行

Python 3.9 或更新版本，无第三方运行时依赖。在仓库根目录执行：

- 测试：`PYTHONPATH=src python3 -B -m unittest discover -s tests -v`。
- 基础演示：`PYTHONPATH=src python3 -B -m examples.demo`。
- 猜测实验：`PYTHONPATH=src python3 -B -m examples.privacy_experiment`。
- 重做五组性能测量：`PYTHONPATH=src python3 -B -m benchmarks.benchmark --repetitions 5 --output-dir results-new`。

测试、演示和基准各有独立入口；先执行测试，再测性能。基准自身会核对测量夹具的有效开封和哈希次数。显式指定新的输出目录可保留已有测量。`-B` 防止生成 Python 缓存。

需要在其他程序或交互环境导入时，可在自己的虚拟环境运行 `python3 -m pip install -e .` 做可编辑安装，然后直接使用 `from merkle_commitment import commit, verify`。安装工具可能需要获取 setuptools；上述源码运行命令不需要安装。

## 协议与验证结果

- [作业要求](docs/作业要求.md)
- [方案设计与安全性分析](docs/方案设计.md)
- [性能与验证结果](results/性能与验证结果.md)
- [原始样本](results/results.json)

`commit(messages)` 返回公开 Commitment 和承诺方私有状态。`state.open(index)` 返回消息及 MerkleProof；`verify(commitment, index, message, proof)` 核对验证者保存的承诺和期望位置。完整开封使用 `state.open_all()` 与 `verify_all()`。

字符串按 UTF-8 编码，空向量拒绝，空消息允许，重复值按位置区分。每次承诺生成新的独立随机值。验证者需要提前保存可信承诺；隐藏性在文档说明的随机预言机及随机性假设下分析。

正式计算、测试和基准均不调用现成哈希或 Merkle Tree 实现。静态向量是公开答案数据。组员姓名、学号及分工按要求暂留空。涉及协议、编码或安全假设的合作修改，应同步更新文档和测试，使用独立分支及 Pull Request。
