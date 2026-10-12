"""性能实验 P1–P4：真实计时、独立工作量观测、JSON 和 SVG。

PYTHONPATH=src .venv/bin/python -B experiments/performance.py
--quick 仅检查连通性；--from-json FILE 只重绘。计时期间不并行运行别的实验。
"""
import argparse
from datetime import datetime
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import tempfile
import time
from unittest.mock import patch

os.environ.setdefault('MPLCONFIGDIR', str(Path(tempfile.gettempdir()) / 'mtc-matplotlib'))
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from merkle_commitment import tree as mt
from merkle_commitment.sha3 import RATE_BYTES

ROOT = Path(__file__).resolve().parents[1]


def environment():
    """同时记录后端与环境，避免把未来 C 结果混入 Python 曲线。"""
    return {
        'backend': 'handwritten-python-sha3',
        'python': platform.python_version(), 'platform': platform.platform(),
        'timestamp': datetime.now().astimezone().isoformat(),
        'commit': subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
        ).strip(),
        'dirty': bool(subprocess.check_output(
            ['git', 'status', '--porcelain'], cwd=ROOT, text=True,
        ).strip()),
    }


def measure(operation, quick, groups=9):
    """预热一次；校准 batch；保存逐组每调用秒数、中位数及四分位数。

    #! full 默认 9 组，P4 大 k 显式指定 3 组，目标每组 >=0.2s；
    #! quick：3 组，目标 >=0.01s。
    batch 由 pilot 决定且固定；正式组可能因机器波动略短于目标。
    保留函数调用、循环及结果释放成本，不扣减空循环制造负时间。
    """
    groups, target = (3, 0.01) if quick else (groups, 0.2)
    operation()
    batch = 1
    while True:
        started = time.perf_counter_ns()
        for _ in range(batch):
            operation()
        elapsed = (time.perf_counter_ns() - started) / 1e9
        if elapsed >= target:
            break
        batch = max(batch + 1, math.ceil(batch * target / max(elapsed, 1e-9) * 1.05))
    samples = []
    for _ in range(groups):
        started = time.perf_counter_ns()
        for _ in range(batch):
            operation()
        samples.append((time.perf_counter_ns() - started) / 1e9 / batch)
    q1, _, q3 = statistics.quantiles(samples, n=4, method='inclusive')
    return {'samples_seconds': samples, 'batch': batch, 'groups': groups,
            'median_seconds': statistics.median(samples),
            'q1_seconds': q1, 'q3_seconds': q3,
            'calibration_target_seconds': target}


def hash_work(operation):
    """在独立、不计时的调用中观察哈希长度直方图，保留计数的依据。

    置换次数根据实际输入长度和 SHA3 后缀求得，未在计时区间包装 H。
    """
    original = mt.H
    lengths = {}

    def counted(data):
        """只增加观测，不替换哈希算法。"""
        lengths[len(data)] = lengths.get(len(data), 0) + 1
        return original(data)

    with patch.object(mt, 'H', counted):
        operation()
    return {
        'input_length_counts': lengths,
        'hash_calls': sum(lengths.values()),
        'permutations': sum((length // RATE_BYTES + 1) * count
                            for length, count in lengths.items()),
    }


def fixture(messages, rng):
    """预先建树、制备首/中/末及随机位置证明，并先核对对象和字节入口。"""
    commitment, tree = mt.commit(messages)
    n = len(messages)
    indices = sorted({0, n // 2, n - 1, *rng.sample(range(n), min(n, 13))})
    openings = [(index, *tree.open(index)) for index in indices]
    full = tree.open_all()
    for index, message, proof in openings:
        assert mt.verify(commitment, index, message, proof)
    index, message, proof = openings[0]
    assert mt.verify(commitment.to_bytes(), index, message, proof.to_bytes())
    assert mt.verify_all(commitment, full)
    return commitment, tree, openings, full


def operations(messages, commitment, tree, openings, full):
    """构造对象接口的计时操作；每次 open/verify 循环使用预生成位置。"""
    indices = itertools.cycle([item[0] for item in openings])
    proofs = itertools.cycle(openings)
    return {
        'commit': lambda: mt.commit(messages),
        'open': lambda: tree.open(next(indices)),
        'verify': lambda: mt.verify(commitment, *next(proofs)),
        'verify_all': lambda: mt.verify_all(commitment, full),
    }


def curve(ax, rows, field, operation, scale, label=None):
    """IQR 表示组间观测离散程度，不标为置信区间。"""
    x = [row[field] for row in rows]
    medians = [row[operation]['median_seconds'] * scale for row in rows]
    q1 = [row[operation]['q1_seconds'] * scale for row in rows]
    q3 = [row[operation]['q3_seconds'] * scale for row in rows]
    ax.plot(x, medians, '.-', label=label or operation, linewidth=1)
    ax.fill_between(x, q1, q3, alpha=0.15)


def save(fig, directory, name, preview):
    """图由 JSON 中保存的样本生成，PNG 仅用于本地审查。"""
    fig.tight_layout()
    fig.savefig(directory / (name + '.svg'))
    if preview:
        preview.mkdir(parents=True, exist_ok=True)
        fig.savefig(preview / (name + '.png'), dpi=140)
    plt.close(fig)


class ExperimentP1_RawSHA3BlockCost:
    """性能实验 P1：绕过树，隔离 SHA3 输入长度及 rate 边界。

    #! full：0/32/64/4096 B、130..142 B、266..278 B；quick：135/136/273 B。
    #! C 后端可加入 64 KiB/1 MiB；短调用需重新校准 batch，不沿用 Python batch。
    输入 bytes 在计时前构造；包括填充、吸收、置换、输出，不含 hex 转换。
    """
    def run(self, rng, quick):
        """对同一长度的全 a 字节串反复计算，采集完整 digest 调用成本。"""
        lengths = [135, 136, 273] if quick else sorted(
            {0, 32, 64, 4096, *range(130, 143), *range(266, 279)}
        )
        rows = []
        for length in lengths:
            message = b'a' * length
            rows.append({'message_bytes': length,
                         'permutations': length // RATE_BYTES + 1,
                         'hash': measure(lambda: mt.H(message), quick)})
            print(f'P1 length={length}', flush=True)
        return {'rows': rows, 'input': 'repeated byte a'}

    def plot(self, data, directory, preview):
        """局部窗口展示跳跃，全局 panel 展示重复吸收的增长。"""
        fig, axes = plt.subplots(1, 3, figsize=(13, 4))
        for ax, interval in zip(axes, ((0, 4096), (130, 142), (266, 278))):
            rows = [r for r in data['rows'] if interval[0] <= r['message_bytes'] <= interval[1]]
            curve(ax, rows, 'message_bytes', 'hash', 1000)
            if interval[0]:
                ax.axvline(136 if interval[0] == 130 else 272, linestyle='--',
                           color='grey', label='Extra padding block')
            else:
                ax.set_xscale('symlog', linthresh=32)
            ax.set(xlabel='Raw SHA3 input bytes', ylabel='Time (ms)')
            ax.legend(fontsize=8)
        fig.suptitle('P1 | SHA3-256: median and IQR; Python')
        save(fig, directory, 'performance-P1', preview)


class ExperimentP2_TreeSizeCost:
    """性能实验 P2：32 B 消息，二次幂前/后和完整树对照。

    #! full：n=1 及 2^d-1/2^d/2^d+1，d=(3,5,7,8,9,10,11,12)，最大 4097。
    #! quick：n=(1,8,9)。C 后端验收后可把 d 扩至 16/18，仍保留重叠点。
    每棵树只制备至多 16 个位置以免样本准备变成全量开封测试。
    """
    def run(self, rng, quick):
        """各计时操作分开，额外计数独立于计时；open 的哈希数必须为零。"""
        sizes = [1, 8, 9] if quick else sorted(
            {1, *(2**d + offset for d in (3, 5, 7, 8, 9, 10, 11, 12)
                  for offset in (-1, 0, 1))}
        )
        rows = []
        for n in sizes:
            messages = [i.to_bytes(8, 'big') + b'x' * 24 for i in range(n)]
            commitment, tree, openings, full = fixture(messages, rng)
            ops = operations(messages, commitment, tree, openings, full)
            row = {'n': n, 'capacity': 1 << (n - 1).bit_length(),
                   'depth': (n - 1).bit_length(), 'indices': [item[0] for item in openings],
                   'proof_bytes': len(openings[0][2].to_bytes())}
            for name, operation in ops.items():
                row[name] = measure(operation, quick)
            row['work'] = {name: hash_work(ops[name]) for name in ('commit', 'open', 'verify')}
            # N 个叶 + N-1 个内部节点 + 1 次最终承诺封装，共 2N 次哈希。
            assert row['work']['commit']['hash_calls'] == 2 * row['capacity']
            assert row['work']['verify']['hash_calls'] == row['depth'] + 2
            assert row['work']['open']['hash_calls'] == 0
            # 节点摘要各 32 B；每个真实叶另存 32 B nonce 和 32 B 消息。
            row['logical_storage_bytes'] = (2 * row['capacity'] - 1) * 32 + n * 64
            rows.append(row)
            print(f'P2 n={n}: commit={row["commit"]["median_seconds"]:.3f}s', flush=True)
        return {'message_bytes': 32, 'rows': rows}

    def plot(self, data, directory, preview):
        """时间分面板，模型按 n 最大点归一化；明确它不是额外测量。"""
        rows = data['rows']
        model_n = list(range(1, rows[-1]['n'] + 1))
        model_h = [(n - 1).bit_length() for n in model_n]
        fig, axes = plt.subplots(2, 2, figsize=(12, 8))
        curve(axes[0, 0], rows, 'n', 'commit', 1)
        curve(axes[0, 0], rows, 'n', 'verify_all', 1)
        factor = rows[-1]['commit']['median_seconds'] / (2 * rows[-1]['capacity'])
        axes[0, 0].step(model_n, [2 * (1 << h) * factor for h in model_h], where='post',
                        linestyle='--', color='black', label='2N model, scaled at max n')
        axes[0, 0].set_ylabel('Time (s)')
        curve(axes[0, 1], rows, 'n', 'open', 1e6)
        axes[0, 1].set_ylabel('Time (microseconds)')
        curve(axes[1, 0], rows, 'n', 'verify', 1e3)
        factor = rows[-1]['verify']['median_seconds'] * 1000 / (rows[-1]['depth'] + 2)
        axes[1, 0].step(model_n, [(h + 2) * factor for h in model_h], where='post',
                        linestyle='--', color='black', label='h+2 model, scaled at max n')
        axes[1, 0].set_ylabel('Time (ms)')
        axes[1, 1].plot([r['n'] for r in rows], [r['proof_bytes'] for r in rows],
                        '.-', label='Measured v1 encoding')
        axes[1, 1].step(model_n, [43 + 32 * h for h in model_h],
                        where='post', linestyle='--', label='43+32h (analytic staircase)')
        axes[1, 1].set_ylabel('Proof bytes (message excluded)')
        for ax in axes.flat:
            ax.set_xscale('log', base=2)
            ax.set_xlabel('Real leaves n (boundary pairs 2^d / 2^d+1)')
            ax.legend(fontsize=8)
            ax.grid(alpha=0.2)
        fig.suptitle('P2 | Tree size: object APIs, median and IQR; Python')
        save(fig, directory, 'performance-P2', preview)


class ExperimentP3_MessageLengthCost:
    """性能实验 P3：n=N=32，消息长度影响建树、开封和单项验证的程度。

    #! full：0/16/32/64/128/256/512/1024/4096 B，70..86、206..222 B。
    #! quick：78/79/214/215 B；C 后端可到 1 MiB，计时与存储预算仍需报告。
    固定树形、同长 x 消息；57 B 叶编码开销使额外块出现于 79/215 B。
    """
    def run(self, rng, quick):
        """open 返回已有消息引用，作为无叶哈希的控制操作。"""
        lengths = [78, 79, 214, 215] if quick else sorted(
            {0, 16, 32, 64, 128, 256, 512, 1024, 4096,
             *range(70, 87), *range(206, 223)}
        )
        rows = []
        for length in lengths:
            messages = [b'x' * length] * 32
            commitment, tree, openings, full = fixture(messages, rng)
            ops = operations(messages, commitment, tree, openings, full)
            row = {'message_bytes': length, 'leaf_input_bytes': 57 + length}
            for name in ('commit', 'open', 'verify'):
                row[name] = measure(ops[name], quick)
            row['work'] = {name: hash_work(ops[name]) for name in ('commit', 'verify')}
            leaf_permutations = (57 + length) // RATE_BYTES + 1
            # 建树另有 31 个父节点和 1 次封装；单项验证另有 5 层路径和 1 次封装。
            assert row['work']['commit']['permutations'] == 32 * leaf_permutations + 32
            assert row['work']['verify']['permutations'] == leaf_permutations + 6
            rows.append(row)
            print(f'P3 length={length}', flush=True)
        return {'n': 32, 'input': 'repeated byte x', 'rows': rows}

    def plot(self, data, directory, preview):
        """全局与两个局部窗口各一列；每行独立单位显示三种操作。"""
        fig, axes = plt.subplots(3, 3, figsize=(13, 10))
        for col, (lo, hi) in enumerate(((0, 4096), (70, 86), (206, 222))):
            rows = [r for r in data['rows'] if lo <= r['message_bytes'] <= hi]
            for row, (name, scale, unit) in enumerate(
                    (('commit', 1000, 'ms'), ('open', 1e6, 'us'), ('verify', 1000, 'ms'))):
                ax = axes[row, col]
                curve(ax, rows, 'message_bytes', name, scale)
                if col:
                    ax.axvline(79 if col == 1 else 215, color='grey', linestyle='--')
                else:
                    ax.set_xscale('symlog', linthresh=32)
                ax.set(xlabel='Message bytes (leaf input = 57 + message)',
                       ylabel=f'{name} ({unit})')
                ax.grid(alpha=0.2)
        fig.suptitle('P3 | Message length, n=32: median and IQR; Python')
        save(fig, directory, 'performance-P3', preview)




def _count_stored_digest_reads(tree, operation):
    """在生成调用中计数 level[position]；只取已有摘要，不衡量硬件行为。"""
    reads = 0

    class ObservedLevel:
        """保留原摘要对象，整数下标取用一次就记录一次。"""
        def __init__(self, values):
            self.values = values

        def __getitem__(self, position):
            nonlocal reads
            reads += 1
            return self.values[position]

    levels = tuple(ObservedLevel(level) for level in tree._levels)
    with patch.object(tree, '_levels', levels):
        result = operation()
    return result, reads


def _count_parent_merges(operation):
    """验证成功后返回真实父合并及 H 调用数；不在计时组中使用包装。"""
    merges, original = 0, mt._parent_hash

    def observed(left, right):
        """一次父节点合成记一，仍使用原哈希实现。"""
        nonlocal merges
        merges += 1
        return original(left, right)

    def checked():
        """计数调用也核对验证结果，避免失败短路冒充较少工作量。"""
        assert operation()

    with patch.object(mt, '_parent_hash', observed):
        work = hash_work(checked)
    return {'parent_merges': merges, **work}


class ExperimentP4_BatchproofSharingCost:
    """P4：同一组位置的独立/批量证明大小、两个操作次数和耗时比较。

    #! full：N=4096，k=2^0..2^12；连续/随机各 300 个结构样本，分散 1 个。
    #! 默认计时 k=(1,8,64,256)；--large-timing 再加 512/1024/4096。
    #! quick：N=64，k=(1,8,16,64)，每类三个结构样本，计时到 16。
    #! 32 B 消息；生成不含建树/编码，验证使用提前准备的对象。
    完整端点只做一次实际计数；三类位置在 k=N 时共享该唯一端点。
    C 后端验收后可扩大 N，保持两个操作指标和 Python 重叠点。
    """
    def run(self, rng, quick, large_timing=False):
        """先廉价采集结构分布，再对中位结构成对计时并执行真实计数。"""
        n = 64 if quick else 4096
        sizes = [1, 8, 16, 64] if quick else [2**power for power in range(13)]
        timing_sizes = {1, 8, 16} if quick else {1, 8, 64, 256}
        if large_timing and not quick:
            timing_sizes.update((512, 1024, 4096))
        trials, depth = (3 if quick else 300), (n - 1).bit_length()
        messages = [i.to_bytes(8, 'big') + b'x' * 24 for i in range(n)]
        commitment, tree = mt.commit(messages)
        topology_rows, timing_rows, count_rows = [], [], []
        for k in sizes:
            patterns = ('all',) if k == n else ('contiguous', 'dispersed', 'random')
            for pattern in patterns:
                rows = []
                sample_count = 1 if pattern in ('dispersed', 'all') else trials
                for trial in range(sample_count):
                    if pattern == 'contiguous':
                        start = rng.randrange(n - k + 1)
                        indices = tuple(range(start, start + k))
                    elif pattern == 'random':
                        indices = tuple(sorted(rng.sample(range(n), k)))
                    else:
                        indices = tuple(j * n // k for j in range(k))
                    proof, reads = _count_stored_digest_reads(
                        tree, lambda: tree.prove_many(indices),
                    )
                    siblings = len(proof.siblings)
                    assert reads == siblings
                    batch_bytes = len(proof.to_bytes())
                    assert batch_bytes == 13 + 40 * k + 32 * siblings
                    row = {
                        'n': n, 'k': k, 'distribution': pattern, 'trial': trial,
                        'indices': indices, 'single_bytes': k * (43 + 32 * depth),
                        'batch_bytes': batch_bytes, 'single_siblings': k * depth,
                        'batch_siblings': siblings,
                        'bytes_per_position': {'single': 43 + 32 * depth,
                                               'batch': batch_bytes / k},
                        'saving_fraction': 1 - batch_bytes / (k * (43 + 32 * depth)),
                        'generation_work': {'batch_stored_digest_reads': reads,
                                            'expected_single_stored_digest_reads': k * depth},
                        'expected_verify_work': {
                            'single_parent_merges': k * depth, 'batch_parent_merges': k + siblings - 1,
                            'single_hash_calls': k * (depth + 2), 'batch_hash_calls': 2 * k + siblings,
                        },
                    }
                    rows.append(row)
                topology_rows.extend(rows)
                print(f'P4 k={k}, {pattern}: {sample_count} structures', flush=True)
                if k not in timing_sizes and k != n:
                    continue
                median_siblings = sorted(row['batch_siblings'] for row in rows)[len(rows) // 2]
                selected = next(row for row in rows if row['batch_siblings'] == median_siblings)
                indices = tuple(selected['indices'])
                opened = tuple(tree.open(i) for i in indices)
                batch_messages, proof = tree.open_many(indices)

                def single_open():
                    """含 k 个消息引用读取与独立证明构造。"""
                    return tuple(tree.open(i) for i in indices)

                def batch_open():
                    """同样含 k 个消息引用读取和一次批量证明构造。"""
                    return tree.open_many(indices)

                def single_verify():
                    """提前准备的 k 份对象证明，各自与同一公开承诺核对。"""
                    return all(mt.verify(commitment, i, *item) for i, item in zip(indices, opened))

                def batch_verify():
                    """提前准备的批量对象，使用正式共享验证器。"""
                    return mt.verify_many(commitment, indices, batch_messages, proof)

                measured = {}
                for label, generate, verify in (('single', single_open, single_verify),
                                                ('batch', batch_open, batch_verify)):
                    _, reads = _count_stored_digest_reads(tree, generate)
                    measured[label] = {'stored_digest_reads': reads, **_count_parent_merges(verify)}
                expected = selected['expected_verify_work']
                for label in ('single', 'batch'):
                    assert measured[label]['parent_merges'] == expected[label + '_parent_merges']
                    assert measured[label]['hash_calls'] == expected[label + '_hash_calls']
                    assert measured[label]['permutations'] == measured[label]['hash_calls']
                assert measured['single']['stored_digest_reads'] == k * depth
                assert measured['batch']['stored_digest_reads'] == len(proof.siblings)
                assert sum(len(item[1].to_bytes()) for item in opened) == selected['single_bytes']
                observed = {'n': n, 'k': k, 'distribution': pattern,
                            'selected_trial': selected['trial'], 'indices': indices,
                            'measured_work': measured}
                count_rows.append(observed)
                if k in timing_sizes:
                    groups = 9 if k < 64 else 3
                    timed = dict(observed)
                    for name, operation in (('single_open', single_open), ('batch_open', batch_open),
                                            ('single_verify', single_verify), ('batch_verify', batch_verify)):
                        timed[name] = measure(operation, quick, groups=groups)
                    timing_rows.append(timed)
                    print(f'P4 timed k={k}, {pattern}', flush=True)
        return {
            'parameters': {'n': n, 'message_bytes': 32, 'sizes': sizes,
                           'structure_trials': trials, 'timing_sizes': sorted(timing_sizes),
                           'large_timing': large_timing},
            'topology_rows': topology_rows, 'timing_rows': timing_rows, 'count_rows': count_rows,
        }

    def plot(self, data, directory, preview):
        """结构分布给中位数/IQR，计数实测加点，时间只画实际采样的 k。"""
        topology = data['topology_rows']
        sizes = sorted({row['k'] for row in topology})
        depth = (data['parameters']['n'] - 1).bit_length()
        colors = dict(zip(('contiguous', 'dispersed', 'random'), ('C0', 'C1', 'C2')))

        def structural(ax, field):
            """同一分布按 k 汇总；完整集合端点可用于三条分布曲线。"""
            for pattern, color in colors.items():
                medians, lowers, uppers = [], [], []
                for k in sizes:
                    values = [field(row) for row in topology
                              if row['k'] == k and row['distribution'] in (pattern, 'all')]
                    quartiles = statistics.quantiles(values, n=4, method='inclusive') if len(values) > 1 else [values[0]] * 3
                    medians.append(statistics.median(values))
                    lowers.append(quartiles[0])
                    uppers.append(quartiles[2])
                ax.plot(sizes, medians, '.-', color=color, label=pattern)
                ax.fill_between(sizes, lowers, uppers, color=color, alpha=0.12)
            ax.set_xscale('log', base=2)
            ax.set_xlabel('Opened positions k')
            ax.grid(alpha=0.2)

        fig, axes = plt.subplots(1, 3, figsize=(13, 4))
        for ax, field in zip(axes, (lambda row: row['batch_bytes'],
                                  lambda row: row['batch_bytes'] / row['k'],
                                  lambda row: row['saving_fraction'] * 100)):
            structural(ax, field)
        axes[0].plot(sizes, [k * (43 + 32 * depth) for k in sizes], 'k--', label='Independent proofs')
        axes[1].axhline(43 + 32 * depth, color='black', linestyle='--', label='Independent proofs')
        axes[2].axhline(0, color='black', linestyle='--')
        for ax, label in zip(axes, ('Total proof bytes', 'Proof bytes / position', 'Saving (%)')):
            ax.set_ylabel(label)
            ax.legend(fontsize=8)
        fig.suptitle(f"P4 | Batch proof size; n={data['parameters']['n']}; messages excluded")
        save(fig, directory, 'performance-P4-size', preview)

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        structural(axes[0], lambda row: row['generation_work']['batch_stored_digest_reads'])
        structural(axes[1], lambda row: row['expected_verify_work']['batch_parent_merges'])
        for ax in axes:
            ax.plot(sizes, [k * depth for k in sizes], 'k--', label='Independent: kh')
            ax.set_ylim(bottom=0)
        for row in data['count_rows']:
            color = colors.get(row['distribution'], 'black')
            work = row['measured_work']['batch']
            axes[0].scatter(row['k'], work['stored_digest_reads'], color=color, marker='x', s=45)
            axes[1].scatter(row['k'], work['parent_merges'], color=color, marker='x', s=45)
        axes[0].set_ylabel('Stored sibling digest reads (generation)')
        axes[1].set_ylabel('Parent merges (verification)')
        for ax in axes:
            ax.legend(fontsize=8)
        fig.suptitle('P4 | Two algorithm operations; x = measured counts; merge curves = predicted')
        save(fig, directory, 'performance-P4-work', preview)

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        for pattern, color in colors.items():
            rows = [r for r in data['timing_rows'] if r['distribution'] in (pattern, 'all')]
            for ax, stage, scale in zip(axes, ('open', 'verify'), (1e6, 1000)):
                # 长虚线加空心方块与实线加实心圆同时区分两种方案；图例也留足线段长度。
                for variant, line, marker in (
                    ('single', (0, (6, 3)), 's'),
                    ('batch', '-', 'o'),
                ):
                    name = variant + '_' + stage
                    x = [r['k'] for r in rows]
                    ax.plot(x, [r[name]['median_seconds'] * scale for r in rows],
                            marker=marker, markersize=5, linewidth=1.5,
                            markerfacecolor='none' if variant == 'single' else color,
                            linestyle=line, color=color, label=f'{pattern}: {variant}')
                    ax.fill_between(x, [r[name]['q1_seconds'] * scale for r in rows],
                                    [r[name]['q3_seconds'] * scale for r in rows],
                                    color=color, alpha=0.08)
                ax.set_xscale('log', base=2)
                ax.set_xlabel('Opened positions k (timed points only)')
                ax.grid(alpha=0.2)
        axes[0].set_ylabel('Open time (microseconds)')
        axes[1].set_ylabel('Verify time (ms)')
        for ax in axes:
            ax.legend(fontsize=7, handlelength=4)
        fig.suptitle('P4 | Paired object APIs: median and IQR; typical topology')
        save(fig, directory, 'performance-P4-time', preview)


def main():
    """顺序运行，完整参数和每组样本写入 JSON；重绘无需重新计时。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--seed', type=int, default=20261012)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'results')
    parser.add_argument('--figure-dir', type=Path, default=ROOT / 'docs/assets/experiments')
    parser.add_argument('--preview-dir', type=Path)
    parser.add_argument('--from-json', type=Path)
    parser.add_argument('--batchproof-only', action='store_true')
    parser.add_argument('--large-timing', action='store_true')
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.figure_dir.mkdir(parents=True, exist_ok=True)
    if args.batchproof_only:
        experiment = ExperimentP4_BatchproofSharingCost()
        if args.from_json:
            data = json.loads(args.from_json.read_text())
        else:
            data = {'environment': environment(), 'seed': args.seed,
                    'mode': 'quick' if args.quick else 'full', 'complete': False,
                    **experiment.run(random.Random(args.seed), args.quick, args.large_timing)}
            data['complete'] = True
            (args.output_dir / 'batchproof-performance.json').write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + '\n'
            )
        experiment.plot(data, args.figure_dir, args.preview_dir)
        return
    experiments = [ExperimentP1_RawSHA3BlockCost(), ExperimentP2_TreeSizeCost(),
                   ExperimentP3_MessageLengthCost()]
    if args.from_json:
        data = json.loads(args.from_json.read_text())
    else:
        data = {'environment': environment(), 'seed': args.seed,
                'mode': 'quick' if args.quick else 'full', 'complete': False,
                'timing': 'warmup; adaptive batch; median/IQR; seconds per call',
                'experiments': {}}
        for number, experiment in enumerate(experiments):
            name, seed = type(experiment).__name__, args.seed + number
            data['experiments'][name] = {'seed': seed, **experiment.run(random.Random(seed), args.quick)}
            data['complete'] = number == len(experiments) - 1
            (args.output_dir / 'performance.json').write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + '\n'
            )
    for experiment in experiments:
        experiment.plot(data['experiments'][type(experiment).__name__],
                        args.figure_dir, args.preview_dir)


# TODO(C-BACKEND): 自写 C 的完整 digest 通过 NIST/协议对照后，局部替换 mt.H；
# 保留 Python/C 重叠点，单独记录后端和编译信息，重新校准 batch 后扩大 #! 范围。
#
# P4 实测 batch proof：连续/分散/随机、总量/均摊、独立操作计数和配对时间。
# --batchproof-only 保留 P1-P3 数据；--large-timing 才启用大 k 重复计时。

if __name__ == '__main__':
    main()
