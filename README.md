# Merkle Tree Commitment

应用密码学课程作业：用手写 SHA3-256 和 Merkle 树承诺一组消息，支持单项、批量和完整开封。保留 Python 实现，并提供自写 C 哈希后端。

## 安装与演示

需要 Python 3.9+；Mac 构建 C 模块需要 Xcode Command Line Tools。以下命令均在项目根目录执行。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[experiments]'
PYTHONPATH=src .venv/bin/python -B -m examples.demo
```

演示包含有效开封、篡改拒绝、批量开封和完整开封。

## 测试与实验

### 正确性检查

同一套测试分别检查 Python 和 C 后端，包括官方哈希向量、差分测试及 Merkle 开封验证。

```sh
PYTHONPATH=src .venv/bin/python -B -m unittest discover -s correctness -v
MTC_SHA3_BACKEND=c PYTHONPATH=src .venv/bin/python -B -m unittest discover -s correctness -v
```

### 运行实验

先用 quick 检查流程：第一条运行八个密码分布实验，第二条运行 P1–P4 性能实验。

```sh
PYTHONPATH=src .venv/bin/python -B experiments/distribution.py --scale quick
PYTHONPATH=src .venv/bin/python -B experiments/performance.py --scale quick
```

省略 `--scale quick` 即为 Python/mid 正式规模。使用 C 大规模实验：

```sh
MTC_SHA3_BACKEND=c PYTHONPATH=src .venv/bin/python -B experiments/distribution.py --scale large
MTC_SHA3_BACKEND=c PYTHONPATH=src .venv/bin/python -B experiments/performance.py --scale large
```

后端默认 Python，若选 C，C 未构建时直接报错；规模可选 quick/mid/large，两种后端均默认 mid。

正式实验较慢，请按顺序运行，不要并行；Python 长任务会要求确认，同组重跑会覆盖运行产物。

只跑批量证明的性能时，在 performance 命令后加 `--batchproof-only`；只跑树级别的实验 B′/C′/D′ 时，在 distribution 命令后加 `--tree-only`（需要已有同组数据）。

### 只重绘结果图表，不重新实验

```sh
PYTHONPATH=src .venv/bin/python -B experiments/distribution.py --from-json all-outputs/python-mid/jsons/distribution.json
PYTHONPATH=src .venv/bin/python -B experiments/performance.py --from-json all-outputs/python-mid/jsons/performance.json
PYTHONPATH=src .venv/bin/python -B experiments/performance.py --batchproof-only --from-json all-outputs/python-mid/jsons/batchproof-performance.json
```

为 C 哈希后端重绘图表时，把路径中的 `python-mid` 换成 `c-large`。较大的原始 JSON 仅保存在本地；若尚无数据，需先运行对应实验。

固定规模的 Python/C 后端对比是一个独立工具：

```sh
PYTHONPATH=src .venv/bin/python -B tools/compare_backends.py
```

## 结果与阅读

- [方案设计](docs/方案设计.md)：算法、安全分析及 Python 教学参考结果。
- [C 扩展介绍及次要组实验结果](docs/C扩展介绍及次要组实验结果.md)：C 实现、大规模结果及噪声说明。
- 运行原始结果：[Python/mid](all-outputs/python-mid/实验结果.md)、[C/large](all-outputs/c-large/实验结果.md)、[后端配对比较](all-outputs/backend-comparison/实验结果.md)。
- [作业要求](docs/作业要求.md)：课程原文。

`all-outputs/` 保存动态 JSON、SVG 和结果提示；`docs/assets/` 保存带日期与随机标识的静态标本。采样和重绘不会自动修改文档标本。

实现位于 `src/merkle_commitment/`，正确性测试位于 `correctness/`，密码学及性能实验位于 `experiments/`。接口及参数的完整定义见方案设计和实验类注释。

## 项目结构

| 路径 | 职责 |
| --- | --- |
| src/merkle_commitment/protocol.py | 承诺与开封的数据类型、字段校验及编解码 |
| src/merkle_commitment/tree.py | 建树、开封和验证 |
| src/merkle_commitment/sha3.py | SHA3-256 算法 |
| src/merkle_commitment/_sha3_c.c | 同一 SHA3-256 的 C11 后端，保持 GIL |
| correctness/ | 六项基干回归，含 C/Python 差分与共享合并检查 |
| examples/ | 基础开封演示 |
| experiments/ | 四个单叶演示、四个树级实验、四个性能实验及绘图（两个脚本） |
| tools/compare_backends.py | 一次固定规模的后端对比工具 |
| docs/ | Python 教学参考的方案设计、主展示图和作业要求 |
| all-outputs/ | 按运行组保存的 JSON、SVG 和实验结果提示 |
| docs/assets/ | 文档采用的静态图快照，与运行产物分开 |

实现代码构成 `merkle_commitment` 包，位于 `src/`；测试和辅助脚本单独组织。组员信息暂留空，提交前填写。合作修改使用独立分支和 Pull Request，协议或安全假设有变化时同步更新文档与测试。
