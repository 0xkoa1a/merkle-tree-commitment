"""单叶 A/B/C/D 与树级 A'/B'/C'/D'；保存原始 JSON 和 SVG。

PYTHONPATH=src .venv/bin/python -B experiments/distribution.py
--scale quick 检查连通性；默认 mid；--from-json FILE 重绘；--tree-only 补跑 B'/C'/D'。
MTC_SHA3_BACKEND=python|c 在进程启动时选定实现。
固定 PRNG 只用于可复现实验输入，生产 commit 的随机源不作改动。
"""
import argparse
from datetime import datetime
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import tempfile
from unittest.mock import patch

os.environ.setdefault('MPLCONFIGDIR', str(Path(tempfile.gettempdir()) / 'mtc-matplotlib'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from merkle_commitment import tree as mt
from merkle_commitment.sha3 import SHA3_BACKEND, backend_info

ROOT = Path(__file__).resolve().parents[1]


def environment():
    """记录实现身份与运行环境；dirty 明确表示提交号不能单独复现。"""
    return {
        **backend_info(),
        'python': platform.python_version(), 'platform': platform.platform(),
        'timestamp': datetime.now().astimezone().isoformat(),
        'commit': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
        ).strip(),
        'dirty': bool(subprocess.check_output(
            ['git', 'status', '--porcelain'], cwd=ROOT, text=True,
        ).strip()),
    }


def confirm_python_run(scale, yes):
    """按已有单块耗时与搜索工作量，在采样前确认超过 90 s 的 Python 任务。"""
    if SHA3_BACKEND == 'python' and scale != 'quick':
        print(f'警告：Python/{scale} 分布实验预计超过 90 秒，'
              'mid 通常需数十分钟；large 仅哈希预算就约 2.5 小时。', file=sys.stderr)
        if not yes and (not sys.stdin.isatty() or input('继续？输入 y 确认：').strip().lower() != 'y'):
            raise SystemExit('已取消；非交互运行须显式提供 --yes。')


def random_bytes(rng, length):
    """确定性实验采样，不充当协议的密码学随机源。"""
    return rng.getrandbits(length * 8).to_bytes(length, 'big')


def flip_bit(value, bit):
    """bit=0 指第一个字节的最高位；只改变一位，不改变长度。"""
    changed = bytearray(value)
    changed[bit // 8] ^= 1 << (7 - bit % 8)
    return bytes(changed)


def difference(left, right):
    """保留逐位 XOR 观测值，以便从 JSON 重算任何位频率或汉明距离。"""
    return bytes(a ^ b for a, b in zip(left, right)).hex()


def distance(xor_hex):
    """兼容 Python 3.9 的 256 位 popcount。"""
    return bin(int(xor_hex, 16)).count('1')


def bit_rates(hex_samples):
    """按从高到低的位顺序求频率；分母是独立样本数。"""
    totals = [0] * 256
    for value in hex_samples:
        for j, byte in enumerate(bytes.fromhex(value)):
            for bit in range(8):
                totals[8 * j + bit] += (byte >> (7 - bit)) & 1
    return [count / len(hex_samples) for count in totals]


def finish(fig, directory, name, preview, data):
    """SVG 保留为正式图；可选 PNG 只用于本地视觉检查。"""
    backend = data.get('backend', 'handwritten-python-sha3')
    # 有的实验只使用 axes 标题；统一在页脚记录后端，不依赖 suptitle 是否存在。
    fig.text(0.99, 0.01, backend, ha='right', fontsize=8)
    fig.tight_layout(rect=(0, 0.035, 1, 1))
    fig.savefig(directory / (name + '.svg'))
    if preview:
        preview.mkdir(parents=True, exist_ok=True)
        fig.savefig(preview / (name + '.png'), dpi=140)
    plt.close(fig)


def hamming_histogram(ax, samples, label):
    """把经验概率与理想独立随机输出的二项 PMF 放到同一单位下。"""
    values = [distance(value) for value in samples]
    quantiles = statistics.quantiles(values, n=20, method='inclusive')
    ax.hist(values, bins=[k - 0.5 for k in range(258)],
            weights=[1 / len(values)] * len(values),
            alpha=0.55, label='Observed')
    x = range(257)
    ax.plot(list(x), [math.comb(256, k) / 2**256 for k in x],
            color='black', label='Binomial(256, 0.5)')
    ax.set(xlabel='Changed output bits', ylabel='Probability per bit count',
           title=f'{label}: n={len(values)}, mean={statistics.mean(values):.2f}, '
                 f'sd={statistics.stdev(values):.2f}\n'
                 f'5% / 50% / 95%: {quantiles[0]:g} / '
                 f'{statistics.median(values):g} / {quantiles[18]:g}')
    ax.legend(fontsize=8)
    ax.set_xlim(min(80, min(values) - 1), max(176, max(values) + 1))


class ExperimentA_LeafCommitAvalanche:
    """实验 A：固定 n=8、i=3，消息和 nonce 均为 32 B，每次只翻转一位。

    #! mid 每组 10,000 对；分别改变 message 或 nonce，位位置均匀采样。
    #! quick 每组 128 对；large 每组 100,000 对，两个后端参数相同。
    XOR 原始记录保存全部输出位；95% 零假设参考带逐位定义，不是同时保证。
    """
    def run(self, rng, scale):
        """保持其余编码字段相同，隔离输入的单比特改动。"""
        count = {'quick': 128, 'mid': 10000, 'large': 100000}[scale]
        groups = {}
        for field in ('message', 'nonce'):
            rows = []
            for _ in range(count):
                message, nonce = random_bytes(rng, 32), random_bytes(rng, 32)
                bit = rng.randrange(256)
                base = mt._leaf_hash(8, 3, message, nonce)
                changed = mt._leaf_hash(
                    8, 3, flip_bit(message, bit) if field == 'message' else message,
                    flip_bit(nonce, bit) if field == 'nonce' else nonce,
                )
                rows.append({'input_bit': bit, 'xor': difference(base, changed)})
            groups[field] = rows
            print(f'A {field}: {count} pairs', flush=True)
        return {'n': 8, 'index': 3, 'message_bytes': 32, 'pairs': count, 'groups': groups}

    def plot(self, data, directory, preview):
        """并排展示距离分布与逐位翻转率，避免只看一个平均值。"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 7))
        for row, (field, records) in enumerate(data['groups'].items()):
            samples = [record['xor'] for record in records]
            hamming_histogram(axes[row, 0], samples, field)
            ax = axes[row, 1]
            band = 1.96 * math.sqrt(0.25 / len(samples))
            ax.axhspan(0.5 - band, 0.5 + band, alpha=0.15,
                       label='Pointwise 95% null band')
            ax.plot(bit_rates(samples), linewidth=0.7)
            ax.axhline(0.5, color='black', linewidth=1)
            ax.set(xlabel='Output bit (MSB first)', ylabel='Flip frequency',
                   title=f'{field}: marginal frequencies')
            ax.legend(fontsize=8)
        fig.suptitle('A | Leaf avalanche diagnostic (not a hiding proof)')
        finish(fig, directory, 'distribution-A', preview, data)


class ExperimentB_LowEntropyInputBias:
    """实验 B：同一 n=8、i=3，比较一字节消息 0/1 的输出边际分布。

    #! mid 每类 10,000 个独立采样的 32 B nonce；quick 每类 128。
    #! large 每类 100,000；仍不能估计完整 256 位分布的距离。
    两组摘要一一配对，无样本复用；置信带是近似逐位零假设带。
    """
    def run(self, rng, scale):
        """保存两组完整摘要，支持重新计算边际差和配对汉明距离。"""
        count = {'quick': 128, 'mid': 10000, 'large': 100000}[scale]
        groups = {}
        for message in ('0', '1'):
            groups[message] = [
                mt._leaf_hash(8, 3, message.encode(), random_bytes(rng, 32)).hex()
                for _ in range(count)
            ]
        return {'n': 8, 'index': 3, 'samples_per_class': count, 'digests': groups}

    def plot(self, data, directory, preview):
        """单图展示类别逐位频率差；完整摘要仍留在 JSON 中。"""
        left, right = data['digests']['0'], data['digests']['1']
        fig, ax = plt.subplots(figsize=(8, 4))
        delta = [a - b for a, b in zip(bit_rates(left), bit_rates(right))]
        band = 1.96 * math.sqrt(0.5 / len(left))
        ax.axhspan(-band, band, alpha=0.15, label='Pointwise 95% null band')
        ax.plot(delta, linewidth=0.8)
        ax.axhline(0, color='black', linewidth=1)
        ax.set(xlabel='Output bit (MSB first)', ylabel='Frequency(0) - frequency(1)',
                    title=f'Two independent classes, n={len(left)} each')
        ax.legend(fontsize=8)
        fig.suptitle('B | Leaf primer: low-entropy input classes')
        finish(fig, directory, 'distribution-B', preview, data)


class ExperimentC_ReducedNonceSearch:
    """实验 C：真实叶编码不变，仅把 nonce 熵缩成 t 位，实际执行穷举。

    #! mid t=(4,6,8,10)，每档 20 次；候选消息为数字 0..9。
    #! quick t=(4,6)，每档 2 次；large t=(4,6,8,10,12,14)，每档 32 次。
    #! 每多一位成本约翻倍，真实 256 位始终不枚举。
    固定 n=8、i=3；消息按单字节数字编码，nonce 字段始终为 32 B。
    目标均匀采样；搜索顺序为先消息后 nonce，nonce 的其余位固定为 0。
    查询数只计搜索，不含一次目标摘要生成；找到的输入须与目标完全一致。
    """
    def run(self, rng, scale):
        """计数每次真实哈希查询，记录找到的消息及 nonce 以核对恢复。"""
        trials = {'quick': 2, 'mid': 20, 'large': 32}[scale]
        bits_values = {'quick': (4, 6), 'mid': (4, 6, 8, 10),
                       'large': (4, 6, 8, 10, 12, 14)}[scale]
        rows = []
        for bits in bits_values:
            for trial in range(trials):
                target_message = rng.randrange(10)
                target_nonce = rng.randrange(2**bits)
                target = mt._leaf_hash(8, 3, str(target_message).encode(),
                                       target_nonce.to_bytes(32, 'big'))
                for rank in range(10 * 2**bits):
                    message, nonce = divmod(rank, 2**bits)
                    candidate = mt._leaf_hash(8, 3, str(message).encode(),
                                             nonce.to_bytes(32, 'big'))
                    if candidate == target:
                        assert (message, nonce) == (target_message, target_nonce)
                        rows.append({'bits': bits, 'trial': trial, 'queries': rank + 1,
                                     'message': message, 'nonce': nonce})
                        break
            print(f'C t={bits}: {trials} searches complete', flush=True)
        return {'trials_per_bits': trials, 'candidates': 10, 'rows': rows}

    def plot(self, data, directory, preview):
        """一幅查询数分布图解释 nonce 位数的指数成本。"""
        bits = sorted({row['bits'] for row in data['rows']})
        samples = [[row['queries'] for row in data['rows'] if row['bits'] == b]
                   for b in bits]
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.boxplot(samples, positions=bits, widths=0.9)
        ax.plot(bits, [(10 * 2**b + 1) / 2 for b in bits], '--',
                     label='Expected mean: (10*2^t + 1)/2')
        ax.scatter(bits, [statistics.mean(s) for s in samples], label='Sample mean')
        ax.set(yscale='log', xlabel='Nonce entropy t (bits)', ylabel='Hash queries',
                    title=f'{data["trials_per_bits"]} independent targets per t')
        ax.legend(fontsize=8)
        fig.suptitle('C | Leaf primer: exhaustive search')
        finish(fig, directory, 'distribution-C', preview, data)


class ExperimentD_ProjectedDigestCollision:
    """实验 D：投影为前 b 位后，搜寻不同消息的首次碰撞。

    #! mid b=(8,12,16,20)，每档 100 次；quick b=(8,12)，每档 5 次。
    #! large b=(8,12,16,20,24)，每档 32 次；控制常识演示预算，成本约为 2^(b/2)。
    固定 n=8、i=3；每 trial 固定独立的 32 B nonce。
    消息为递增的 8 B 整数，确保输入从不重复。
    """
    def run(self, rng, scale):
        """确实计算到碰撞，不从生日公式抽样冒充哈希观测。"""
        trials = {'quick': 5, 'mid': 100, 'large': 32}[scale]
        bits_values = {'quick': (8, 12), 'mid': (8, 12, 16, 20),
                       'large': (8, 12, 16, 20, 24)}[scale]
        rows = []
        for bits in bits_values:
            for trial in range(trials):
                nonce, seen = random_bytes(rng, 32), {}
                counter = 0
                while True:
                    digest = mt._leaf_hash(8, 3, counter.to_bytes(8, 'big'), nonce)
                    projection = int.from_bytes(digest, 'big') >> (256 - bits)
                    if projection in seen:
                        rows.append({
                            'bits': bits, 'trial': trial, 'queries': counter + 1,
                            'first_message': seen[projection], 'second_message': counter,
                            'nonce_hex': nonce.hex(), 'projected_digest': projection,
                        })
                        break
                    seen[projection] = counter
                    counter += 1
            print(f'D b={bits}: {trials} collisions found', flush=True)
        return {'trials_per_bits': trials, 'rows': rows}

    def plot(self, data, directory, preview):
        """箱线图展示离散波动；理论均值与样本均值对应，不混淆中位数。"""
        bits = sorted({row['bits'] for row in data['rows']})
        samples = [[r['queries'] for r in data['rows'] if r['bits'] == b] for b in bits]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.boxplot(samples, positions=bits, widths=1.4)
        ax.plot(bits, [math.sqrt(math.pi / 2) * 2**(b / 2) for b in bits], '--',
                label='Birthday-model mean (asymptotic)')
        ax.scatter(bits, [statistics.mean(s) for s in samples], label='Sample mean')
        ax.set(yscale='log', xlabel='Projected digest bits b',
               ylabel='Queries including the colliding input',
               title=f'D | First collision; {data["trials_per_bits"]} trials per b')
        ax.legend()
        finish(fig, directory, 'distribution-D', preview, data)


class ExperimentAPrime_TreeTamperPropagation:
    """实验 A'（原 E）：固定其余叶，分别改一位，沿证明路径重算。

    #! mid n=(8,32,257,1024)，每规模每类 100 次；均匀采样真实位置。
    #! quick n=(8,32)，每类 4 次；large 再加 n=16384/65536，每类 1,000 次。
    消息和 nonce 均为 32 B，翻转位均匀选自 0..255。
    同一规模复用一棵树；这些观测是条件于该树的样本，不冒称独立树总体。
    """
    def run(self, rng, scale):
        """同时用少量整树重建核对：变化仅落在被改叶的祖先路径。"""
        trials = {'quick': 4, 'mid': 100, 'large': 1000}[scale]
        sizes = {'quick': (8, 32), 'mid': (8, 32, 257, 1024),
                 'large': (8, 32, 257, 1024, 16384, 65536)}[scale]
        groups = []
        for n in sizes:
            messages = [random_bytes(rng, 32) for _ in range(n)]
            # 仅实验构造的树采用记录种子的随机值，生产 API 仍为 secrets。
            with patch.object(mt, 'token_bytes', lambda size: random_bytes(rng, size)):
                commitment, tree = mt.commit(messages)
            opening = tree.open_all()
            rows = []
            for field in ('message', 'nonce'):
                for trial in range(trials):
                    index, bit = rng.randrange(n), rng.randrange(256)
                    message, proof = tree.open(index)
                    changed_message = flip_bit(message, bit) if field == 'message' else message
                    changed_nonce = flip_bit(proof.nonce, bit) if field == 'nonce' else proof.nonce
                    old = mt._leaf_hash(n, index, message, proof.nonce)
                    new = mt._leaf_hash(n, index, changed_message, changed_nonce)
                    distances, position = [distance(difference(old, new))], index
                    for sibling in proof.siblings:
                        old = mt._parent_hash(sibling, old) if position & 1 else mt._parent_hash(old, sibling)
                        new = mt._parent_hash(sibling, new) if position & 1 else mt._parent_hash(new, sibling)
                        distances.append(distance(difference(old, new)))
                        position //= 2
                    old, new = mt._commitment_hash(n, old), mt._commitment_hash(n, new)
                    assert old == commitment.digest
                    distances.append(distance(difference(old, new)))
                    # 每类首例重建全树，比较所有节点，核对每层仅一个节点改变。
                    if trial == 0:
                        values, nonces = list(opening.messages), list(opening.nonces)
                        values[index], nonces[index] = changed_message, changed_nonce
                        rebuilt = mt._levels(tuple(values), tuple(nonces))
                        counts = [sum(a != b for a, b in zip(left, right))
                                  for left, right in zip(tree._levels, rebuilt)]
                        assert counts == [1] * len(rebuilt)
                        assert mt._commitment_hash(n, rebuilt[-1][0]) == new
                    else:
                        counts = None
                    rows.append({'field': field, 'index': index, 'input_bit': bit,
                                 'distances': distances, 'changed_nodes_check': counts})
            groups.append({'n': n, 'trials_per_field': trials, 'rows': rows})
            print(f"A' n={n}: {2 * trials} paths", flush=True)
        return {'groups': groups, 'sampling': 'conditional on one tree per n'}

    def plot(self, data, directory, preview):
        """层 0 是叶，h 是树根，h+1 是含真实叶数的最终承诺。"""
        column_count = 3 if len(data['groups']) > 4 else len(data['groups'])
        row_count = math.ceil(len(data['groups']) / column_count)
        fig, axes = plt.subplots(row_count, column_count,
                                 figsize=(4 * column_count, 4 * row_count),
                                 squeeze=False, sharey=True)
        for ax in axes.flat[len(data['groups']):]:
            ax.set_visible(False)
        for ax, group in zip(axes.flat, data['groups']):
            for field in ('message', 'nonce'):
                samples = [r['distances'] for r in group['rows'] if r['field'] == field]
                columns = list(zip(*samples))
                means = [statistics.mean(c) for c in columns]
                sd = [statistics.stdev(c) for c in columns]
                x = list(range(len(means)))
                ax.plot(x, means, marker='.', label=field)
                ax.fill_between(x, [m - s for m, s in zip(means, sd)],
                                [m + s for m, s in zip(means, sd)], alpha=0.12)
            ax.axhline(128, linestyle='--', color='black', linewidth=1)
            ax.set(title=f'n={group["n"]}, {group["trials_per_field"]}/field',
                   xlabel='Level: leaf=0; last=C', ylabel='Changed digest bits')
            ax.legend(fontsize=8)
        fig.suptitle("A' | Path propagation: mean +/- SD (conditional on one tree)")
        finish(fig, directory, 'distribution-A-prime', preview, data)




def tree_with_nonces(messages, nonces):
    """仅在实验中指定随机值；仍调用生产 commit 完成真实建树。"""
    with patch.object(mt, 'token_bytes', side_effect=nonces):
        return mt.commit(messages)


def commitment_from_leaf(n, index, leaf, siblings):
    """复用不变的兄弟摘要，重算父层和最终承诺封装；共 h+1 次哈希。"""
    current, position = leaf, index
    for sibling in siblings:
        current = (mt._parent_hash(sibling, current) if position & 1
                   else mt._parent_hash(current, sibling))
        position //= 2
    return mt._commitment_hash(n, current)


def counted_search(operation):
    """实际包装 H 计数，只计搜索，不计准备目标或检验见证的哈希。"""
    calls, original = 0, mt.H

    def counted(data):
        """每次真实 digest 调用增加一，不替换算法。"""
        nonlocal calls
        calls += 1
        return original(data)

    with patch.object(mt, 'H', counted):
        result = operation()
    return result, calls


def project_digest(digest, bits):
    """取最高 bits 位；仅用于明确弱化的承诺教学模型。"""
    return int.from_bytes(digest, 'big') >> (256 - bits)


def verify_projected_opening(n, bits, projection, opening):
    """由完整开封真正重建整树，再按弱化承诺的规则比较最终前缀。"""
    if len(opening.messages) != n:
        return False
    levels = mt._levels(opening.messages, opening.nonces)
    root = mt._commitment_hash(n, levels[-1][0])
    return project_digest(root, bits) == projection


class ExperimentBPrime_TreePublicViewBias:
    """实验 B'：挑战消息 0/1 经真实树和邻居开封后的公开视图。

    #! mid：n=(3,8,9)，每规模每类 1,000 个新 nonce 样本；quick：每类 8。
    #! large 每规模每类 10,000；其他叶、目标/邻居位置规则不变。
    #! n=3 时目标/邻居为 0/1；n=8,9 时为 2/3，其他消息固定为 x。
    每对挑战共享其他位置的 nonce，目标 nonce 分别独立采样；
    JSON 保留两类的 C、邻居消息和完整邻居证明，不记录目标私有 nonce。
    """
    def run(self, rng, scale):
        """实际建两棵树并开封邻居，核对证明首个兄弟正是目标叶。"""
        count, groups = {'quick': 8, 'mid': 1000, 'large': 10000}[scale], []
        for n in (3, 8, 9):
            target = 0 if n == 3 else 2
            neighbor = target ^ 1
            labels = {'0': [], '1': []}
            for trial in range(count):
                background_nonces = [random_bytes(rng, 32) for _ in range(n)]
                for label in labels:
                    messages, nonces = [b'x'] * n, list(background_nonces)
                    messages[target], nonces[target] = label.encode(), random_bytes(rng, 32)
                    commitment, tree = tree_with_nonces(messages, nonces)
                    message, proof = tree.open(neighbor)
                    assert proof.siblings[0] == tree._levels[0][target]
                    if trial == 0:
                        assert mt.verify(commitment, neighbor, message, proof)
                    labels[label].append({
                        'root': commitment.digest.hex(),
                        'neighbor_message_hex': message.hex(),
                        'neighbor_proof_hex': proof.to_bytes().hex(),
                    })
            groups.append({'n': n, 'target': target, 'neighbor': neighbor,
                           'samples_per_class': count, 'labels': labels})
            print(f"B' n={n}: {count} samples/class; neighbor opened", flush=True)
        return {'groups': groups}

    def plot(self, data, directory, preview):
        """两图分别观察公开 C 与邻居证明泄露的目标叶，不混为单点实验。"""
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        for group in data['groups']:
            labels = group['labels']
            for ax, field in zip(axes, ('root', 'exposed_leaf')):
                samples = {}
                for label, rows in labels.items():
                    samples[label] = [
                        row['root'] if field == 'root' else
                        mt.SingleProof.from_bytes(bytes.fromhex(row['neighbor_proof_hex']))
                        .siblings[0].hex() for row in rows
                    ]
                delta = [a - b for a, b in zip(bit_rates(samples['0']), bit_rates(samples['1']))]
                ax.plot(delta, linewidth=0.7, alpha=0.75, label=f"n={group['n']}")
        band = 1.96 * math.sqrt(0.5 / data['groups'][0]['samples_per_class'])
        for ax, title in zip(axes, ('Public commitment C', 'Target leaf exposed by neighbor proof')):
            ax.axhspan(-band, band, alpha=0.12, color='grey', label='Pointwise 95% null band')
            ax.axhline(0, color='black', linewidth=0.8)
            ax.set(title=title, xlabel='Output bit (MSB first)',
                   ylabel='Frequency(0) - frequency(1)')
            ax.legend(fontsize=8)
        fig.suptitle(f"B' | Public views; {data['groups'][0]['samples_per_class']} samples/class/n")
        finish(fig, directory, 'distribution-B-prime', preview, data)


class ExperimentCPrime_TreeTargetRecovery:
    """实验 C'：其他叶均开封后，真实执行走根搜索和直接叶匹配两种恢复。

    #! mid：n=(3,8,9)，t=(4,6,8)，每组合 8 个独立目标；quick：t=(4)，2 个。
    #! large：t=(4,6,8,10,12)，每组合 16 个目标，树规模仍为 3/8/9。
    #! 消息为十个单字节数字，目标 nonce 只有低 t 位未知，字段仍为 32 B。
    n=3 时目标为 0，其他规模为 2；每次生成新树和其他叶的完整 256 位 nonce。
    8 个目标是控制 Python 哈希预算的选择；记录全部分布，而非要求均值精确拟合。
    """
    def run(self, rng, scale):
        """攻击者的路径由其他叶的合法证明导出，绝不读取目标的私有 nonce。"""
        trials, rows = {'quick': 2, 'mid': 8, 'large': 16}[scale], []
        bits_values = {'quick': (4,), 'mid': (4, 6, 8), 'large': (4, 6, 8, 10, 12)}[scale]
        for n in (3, 8, 9):
            index = 0 if n == 3 else 2
            for bits in bits_values:
                for trial in range(trials):
                    target_message, target_nonce = rng.randrange(10), rng.randrange(2**bits)
                    messages = [b'x'] * n
                    messages[index] = str(target_message).encode()
                    nonces = [random_bytes(rng, 32) for _ in range(n)]
                    nonces[index] = target_nonce.to_bytes(32, 'big')
                    commitment, tree = tree_with_nonces(messages, nonces)
                    opened = {i: tree.open(i) for i in range(n) if i != index}
                    if trial == 0:
                        assert all(mt.verify(commitment, i, *item) for i, item in opened.items())
                    neighbor = index ^ 1
                    message, proof = opened[neighbor]
                    neighbor_leaf = mt._leaf_hash(n, neighbor, message, proof.nonce)
                    siblings = (neighbor_leaf,) + proof.siblings[1:]
                    exposed_leaf = proof.siblings[0]

                    def search_root():
                        """逐候选调用正式 verify，以公开 C 判断是否恢复。"""
                        for rank in range(10 * 2**bits):
                            value, nonce = divmod(rank, 2**bits)
                            candidate = mt.SingleProof(
                                index=index, nonce=nonce.to_bytes(32, 'big'), siblings=siblings,
                            )
                            if mt.verify(commitment, index, str(value).encode(), candidate):
                                return rank + 1, value, nonce
                        raise AssertionError('target not recovered through commitment')

                    def search_leaf():
                        """用邻居证明公开的叶摘要直接比对，实际重新执行同序枚举。"""
                        for rank in range(10 * 2**bits):
                            value, nonce = divmod(rank, 2**bits)
                            leaf = mt._leaf_hash(n, index, str(value).encode(),
                                                 nonce.to_bytes(32, 'big'))
                            if leaf == exposed_leaf:
                                return rank + 1, value, nonce
                        raise AssertionError('target not recovered through exposed leaf')

                    recovered, root_calls = counted_search(search_root)
                    direct, leaf_calls = counted_search(search_leaf)
                    assert recovered == direct
                    assert recovered[1:] == (target_message, target_nonce)
                    assert root_calls == recovered[0] * (len(siblings) + 2)
                    assert leaf_calls == direct[0]
                    rows.append({
                        'n': n, 'depth': len(siblings), 'bits': bits, 'trial': trial,
                        'target': index, 'message': target_message, 'nonce': target_nonce,
                        'candidate_queries': recovered[0], 'direct_candidate_queries': direct[0],
                        'root_hash_calls': root_calls, 'direct_hash_calls': leaf_calls,
                        'commitment_hex': commitment.to_bytes().hex(),
                        'other_openings': [
                            {'index': i, 'message_hex': value.hex(),
                             'proof_hex': evidence.to_bytes().hex()}
                            for i, (value, evidence) in opened.items()
                        ],
                    })
                print(f"C' n={n}, t={bits}: {trials} targets; both attacks agree", flush=True)
        return {'trials_per_combination': trials, 'rows': rows}

    def plot(self, data, directory, preview):
        """候选分布与实际哈希倍率分开，展示 nonce 熵和树深的不同作用。"""
        rows = data['rows']
        bits = sorted({r['bits'] for r in rows})
        sizes = sorted({r['n'] for r in rows})
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        samples = [[r['candidate_queries'] for r in rows if r['bits'] == b] for b in bits]
        axes[0].boxplot(samples, positions=bits, widths=0.8)
        axes[0].plot(bits, [(10 * 2**b + 1) / 2 for b in bits], '--', label='Uniform-rank mean')
        axes[0].scatter(bits, [statistics.mean(s) for s in samples], label='Sample mean')
        axes[0].set(yscale='log', xlabel='Unknown nonce bits t', ylabel='Candidates to recovery',
                    title='Both attacks recover at the same candidate')
        axes[0].legend(fontsize=8)
        ratios = [statistics.mean(r['root_hash_calls'] / r['direct_hash_calls']
                                  for r in rows if r['n'] == n) for n in sizes]
        axes[1].bar(range(len(sizes)), ratios, label='Observed digest-call ratio')
        axes[1].plot(range(len(sizes)), [(n - 1).bit_length() + 2 for n in sizes],
                     'o--', color='black', label='h+2')
        axes[1].set_xticks(range(len(sizes)))
        axes[1].set_xticklabels([f'n={n}\nh={(n - 1).bit_length()}' for n in sizes])
        axes[1].set(ylabel='Root search / direct-leaf search', title='Tree work, not extra nonce entropy')
        axes[1].legend(fontsize=8)
        fig.suptitle(f"C' | All other leaves opened; {data['trials_per_combination']} targets/n/t")
        finish(fig, directory, 'distribution-C-prime', preview, data)


class ExperimentDPrime_TreeConflictingOpenings:
    """实验 D'：只缩短公开 C，实际提交同一承诺接受的两份冲突完整开封。

    #! mid：n=(3,8,9)，b=(8,12,16)，每组合 12 次；quick：b=(8)，2 次。
    #! large：b=(8,12,16,20)，每组合 32 次，树规模仍为 3/8/9。
    #! 目标位置为 0/2；候选为“我欠你{整数}块”，其他消息与所有 nonce 固定。
    所有内部哈希仍为 256 位，仅教学验证器对最终 C 比较最高 b 位。
    保存两个完整 wire 开封；实际检验弱化规则均接受，正式完整规则拒绝第二份。
    搜索约按 2^(b/2) 增长；不因预算截断困难样本。
    """
    def run(self, rng, scale):
        """搜索只重算变化路径；碰撞见证使用两次整树重建验收。"""
        trials, rows = {'quick': 2, 'mid': 12, 'large': 32}[scale], []
        bits_values = {'quick': (8,), 'mid': (8, 12, 16), 'large': (8, 12, 16, 20)}[scale]
        for n in (3, 8, 9):
            index = 0 if n == 3 else 2
            for bits in bits_values:
                for trial in range(trials):
                    messages = [b'x'] * n
                    nonces = [random_bytes(rng, 32) for _ in range(n)]
                    _, tree = tree_with_nonces(messages, nonces)
                    proof = tree.prove(index)

                    def search_collision():
                        """递增金额保证消息不同，直到最终承诺的投影首次重合。"""
                        seen, amount = {}, 0
                        while True:
                            value = f'我欠你{amount}块'.encode()
                            leaf = mt._leaf_hash(n, index, value, proof.nonce)
                            root = commitment_from_leaf(n, index, leaf, proof.siblings)
                            projected = project_digest(root, bits)
                            if projected in seen:
                                first_amount, first_root = seen[projected]
                                return amount + 1, first_amount, amount, first_root, root, projected
                            seen[projected] = (amount, root)
                            amount += 1

                    found, calls = counted_search(search_collision)
                    queries, first, second, first_root, second_root, projection = found
                    assert calls == queries * (len(proof.siblings) + 2)
                    assert first_root != second_root
                    openings = []
                    for amount in (first, second):
                        values = list(messages)
                        values[index] = f'我欠你{amount}块'.encode()
                        openings.append(mt.FullOpening(messages=tuple(values), nonces=tuple(nonces)))
                    accepted = [verify_projected_opening(n, bits, projection, o) for o in openings]
                    assert all(accepted)
                    original = mt.Commitment(leaf_count=n, digest=first_root)
                    assert mt.verify_all(original, openings[0])
                    assert not mt.verify_all(original, openings[1])
                    rows.append({
                        'n': n, 'depth': len(proof.siblings), 'bits': bits, 'trial': trial,
                        'target': index, 'queries': queries, 'hash_calls': calls,
                        'projection': projection, 'first_amount': first, 'second_amount': second,
                        'first_root': first_root.hex(), 'second_root': second_root.hex(),
                        'first_opening_hex': openings[0].to_bytes().hex(),
                        'second_opening_hex': openings[1].to_bytes().hex(),
                        'weak_accepts': accepted, 'full_accepts_second': False,
                    })
                print(f"D' n={n}, b={bits}: {trials} conflicting-opening pairs verified", flush=True)
        return {'trials_per_combination': trials, 'rows': rows}

    def plot(self, data, directory, preview):
        """左图看生日增长，右图看在不同树深上实际付出的哈希工作量。"""
        rows = data['rows']
        bits = sorted({r['bits'] for r in rows})
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        samples = [[r['queries'] for r in rows if r['bits'] == b] for b in bits]
        axes[0].boxplot(samples, positions=bits, widths=0.8)
        axes[0].plot(bits, [math.sqrt(math.pi / 2) * 2**(b / 2) for b in bits],
                     '--', label='Birthday-model mean')
        axes[0].scatter(bits, [statistics.mean(s) for s in samples], label='Sample mean')
        axes[0].set(yscale='log', xlabel='Public commitment bits b',
                    ylabel='Candidates to conflicting openings')
        axes[0].legend(fontsize=8)
        for n in sorted({r['n'] for r in rows}):
            means = [statistics.mean(r['hash_calls'] for r in rows
                                     if r['n'] == n and r['bits'] == b) for b in bits]
            axes[1].plot(bits, means, '.-', label=f"n={n}, h={(n - 1).bit_length()}")
        axes[1].set(yscale='log', xlabel='Public commitment bits b', ylabel='Search digest calls')
        axes[1].legend(fontsize=8)
        fig.suptitle(f"D' | Two accepted openings per collision; {data['trials_per_combination']} trials/n/b")
        finish(fig, directory, 'distribution-D-prime', preview, data)


def main():
    """按类逐项采样并落盘；重画时只读 JSON，不重新随机采样。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scale', choices=('quick', 'mid', 'large'), default='mid')
    parser.add_argument('--yes', action='store_true', help='Confirm a long Python run without prompting.')
    parser.add_argument('--seed', type=int, default=20261012)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--figure-dir', type=Path)
    parser.add_argument('--preview-dir', type=Path)
    parser.add_argument('--from-json', type=Path)
    parser.add_argument('--tree-only', action='store_true',
                        help="Reuse existing JSON; sample only B'/C'/D'.")
    args = parser.parse_args()
    saved = json.loads(args.from_json.read_text()) if args.from_json else None
    # 运行产物按后端/规模分组；重绘沿用保存的数据身份，不自动修改 docs 快照。
    is_c = saved['environment']['backend'] == 'handwritten-c-sha3' if saved is not None else SHA3_BACKEND == 'c'
    scale = saved.get('scale', saved.get('mode', args.scale)) if saved is not None else args.scale
    scale = 'mid' if scale == 'full' else scale  # 历史记录的 full 对应现有 mid。
    run_dir = ROOT / 'all-outputs' / (('c' if is_c else 'python') + '-' + scale)
    args.output_dir = args.output_dir or run_dir / 'jsons'
    args.figure_dir = args.figure_dir or run_dir / 'svgs'
    if not args.from_json:
        confirm_python_run(args.scale, args.yes)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.figure_dir.mkdir(parents=True, exist_ok=True)
    experiments = [
        ExperimentA_LeafCommitAvalanche(), ExperimentB_LowEntropyInputBias(),
        ExperimentC_ReducedNonceSearch(), ExperimentD_ProjectedDigestCollision(),
        ExperimentAPrime_TreeTamperPropagation(),
        ExperimentBPrime_TreePublicViewBias(), ExperimentCPrime_TreeTargetRecovery(),
        ExperimentDPrime_TreeConflictingOpenings(),
    ]
    if args.from_json:
        data = saved
    else:
        if args.tree_only:
            data = json.loads((args.output_dir / 'distribution.json').read_text())
            # 旧 JSON 只有整体环境：把其身份补到保留条目，不能误标成新后端。
            for entry in data['experiments'].values():
                entry.setdefault('backend', data['environment']['backend'])
                old_scale = entry.get('mode', data.get('scale', data.get('mode', 'full')))
                entry.setdefault('scale', 'mid' if old_scale == 'full' else old_scale)
            data['tree_extension_environment'] = environment()
        else:
            data = {'environment': environment(), 'seed': args.seed,
                    'scale': args.scale, 'experiments': {}}
        data['complete'] = False
        for number, experiment in enumerate(experiments):
            if args.tree_only and number < 5:
                continue
            name = type(experiment).__name__
            seed = data['seed'] + number
            result = experiment.run(random.Random(seed), args.scale)
            data['experiments'][name] = {'seed': seed,
                                        **backend_info(), 'scale': args.scale, **result}
            data['complete'] = number == len(experiments) - 1
            (args.output_dir / 'distribution.json').write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + '\n'
            )
    for experiment in experiments:
        name = type(experiment).__name__
        if name in data['experiments']:
            experiment.plot(data['experiments'][name], args.figure_dir, args.preview_dir)


# 后端在 sha3.py 导入时绑定；每条实验结果单独记录后端与规模，不换正式随机源。
# Batch proof 接口已实现；新的批量分布实验按实际研究需求另加。

if __name__ == '__main__':
    main()
