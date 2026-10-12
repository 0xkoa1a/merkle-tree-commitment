# 作业一：Merkle Tree Commitment

本目录是修订后的基础提交材料。方案使用手写 SHA3-256、每叶子独立 32 字节随机开封值和按位置验证的二叉 Merkle 树，支持完整开封及单项开封。

## 阅读与展示

- [方案分析.md](方案分析.md)：协议定义、编码、安全性分析、实现和组员表。
- [性能与验证结果](results/性能与验证结果.md)：本机实测表格和测量边界。
- results/results.json：环境、每组原始样本及攻击演示结果。
- results/run.log：完整验证与测量输出。
- results/final-validation.log：补强向量完整性断言后的最终验证输出。
- results/independent-review.txt：Luna 独立检查摘要。
- test_vectors.json：140 条官方 NIST SHA3-256 测试向量及来源。

可以先展示旧公开盐方案的枚举恢复，再展示修订方案的承诺、有效开封和篡改拒绝，最后解释 binding/hiding 假设与性能表。有限猜测未命中不能证明隐藏性。

## 运行

Python 3.9 或更新版本，无第三方依赖。先在终端进入本目录。

- 基础演示：`python3 -B merkle_tree.py`。
- 哈希自检：`python3 -B sha3.py`。
- 完整正确性与安全回归、猜测演示：`python3 -B test2.py --tests-only`。
- 重做测试与五组性能测量：`python3 -B test2.py --repetitions 5`。
- 保留已有结果并生成另一次记录：`python3 -B test2.py --repetitions 5 --output-dir results-new`。

测试失败会以非零退出码终止，性能结果只在测试通过后生成。默认基准会覆盖 results 中的记录。加 `-B` 防止生成 Python 缓存。

## 接口与文件

`commit(messages)` 返回公开 Commitment 与承诺方私有 MerkleTree 状态。`state.open(index)` 返回消息和 MerkleProof；`verify(commitment, index, message, proof)` 与验证者保存的承诺比较。`state.open_all()` 返回 FullOpening；`verify_all(commitment, opening)` 验证整个向量。三种公开/开封对象均有严格的二进制编解码接口。

这里的 index 是验证者期待的位置，不能仅信任证明自己声明的位置。字符串先编码成 UTF-8。空向量拒绝，空字节消息允许，相同值在不同位置可以分别开封。同消息重新承诺使用新随机值，摘要通常不同。

| 文件 | 职责 |
| --- | --- |
| sha3.py | 手写 SHA3-256 及静态答案自检 |
| merkle_tree.py | 承诺、私有状态、开封、验证、严格编解码 |
| test_scheme.py | 算法及协议的正确性、安全回归测试 |
| privacy_experiment.py | 公开盐与弱随机值攻击、部分开封后的有限猜测演示 |
| test2.py | 验证入口、重复基准、原始结果和表格生成 |

正式计算、自测和基准均不调用已有哈希或 Merkle Tree 实现。标准库只用于随机字节、数据类、计时、测试、JSON 和环境记录；静态测试向量是答案数据。

组员姓名、学号及分工按要求留空，提交前补齐。原始 zip 在上一级目录保留；上一级审查报告针对原压缩包，是修订前的历史记录。提交代码请使用本目录源码与修订文档，避免把原 zip 或 macOS 元数据当作修订版本。
