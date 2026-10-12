# 应用密码学作业一：Merkle Tree Commitment

本仓库保存作业一的设计、实现、安全性分析和实测结果，供小组共同维护。

- [作业要求](作业一/作业要求.md)
- [运行说明与代码入口](作业一/merkle-tree-commitment/README.md)
- [具体方案与 binding/hiding 分析](作业一/merkle-tree-commitment/方案分析.md)
- [性能与验证结果](作业一/merkle-tree-commitment/results/性能与验证结果.md)
- [修订前审查记录](作业一/审查报告.md)

使用 Python 3.9 或更新版本，无第三方依赖。在 `作业一/merkle-tree-commitment` 目录运行 `python3 -B test2.py --tests-only` 进行验证；运行 `python3 -B test2.py --repetitions 5 --output-dir results-new` 可生成新的性能记录而保留已有结果。

组员信息及实际分工暂留空，提交前补齐。`作业一/merkle-tree-commitment.zip` 是组员最初提供的原始材料；合作修改请使用解压后已修订的源码目录。

建议每项修改使用独立分支和 Pull Request，涉及协议、编码或安全假设的变化应同步更新设计文档与测试。
