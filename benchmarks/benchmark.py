#!/usr/bin/env python3
"""采集哈希、建树和验证的最小性能数据。"""

import argparse
from datetime import datetime
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from unittest.mock import patch

from merkle_commitment import tree as tree_module
from merkle_commitment.sha3 import RATE_BYTES, sha3_256_digest


# TODO(B-MULTIPROOF): 协议和验证器完成后再启用批量证明实验。
# MULTIPROOF_LEAF_COUNT = 1024
# MULTIPROOF_OPEN_COUNTS = (2, 4, 16, 64, 256)
# MULTIPROOF_RANDOM_TRIALS = 300
# 结果字段：leaf_count, opened_count, distribution, trial,
# independent_siblings, deduplicated_siblings, multiproof_siblings,
# proof_bytes, internal_hashes, permutations。


def environment():
    """记录解释最终数据所需的最小运行环境。"""
    try:
        source_commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        working_tree_dirty = bool(
            subprocess.check_output(
                ['git', 'status', '--porcelain'],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        )
    except (OSError, subprocess.CalledProcessError):
        source_commit = 'unavailable'
        working_tree_dirty = None

    return {
        'python': sys.version.split()[0],
        'platform': platform.platform(),
        'timestamp': datetime.now().astimezone().isoformat(),
        'source_commit': source_commit,
        'working_tree_dirty': working_tree_dirty,
    }


def measured(operation, repetitions, batch=1):
    """预热一次，再记录每组调用的平均秒数。"""
    operation()
    samples = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        for _ in range(batch):
            operation()
        elapsed_seconds = (time.perf_counter_ns() - started) / batch / 1e9
        samples.append(elapsed_seconds)

    return {
        'samples_seconds': samples,
        'mean_seconds': statistics.mean(samples),
        'stdev_seconds': (
            statistics.stdev(samples) if repetitions > 1 else 0.0
        ),
        'batch': batch,
    }


def measure_hash_work(messages):
    """在一次独立建树中记录哈希输入长度和置换次数。"""
    original_hash = tree_module.H
    input_lengths = []

    def counted_hash(data):
        input_lengths.append(len(data))
        return original_hash(data)

    with patch.object(tree_module, 'H', counted_hash):
        tree_module.commit(messages)

    # SHA3 后缀始终占空间，因此输入恰好填满 rate 时需要额外一块。
    permutations = sum(
        input_length // RATE_BYTES + 1
        for input_length in input_lengths
    )
    return {
        'hash_calls': len(input_lengths),
        'permutations': permutations,
    }


def logical_storage_bytes(messages, capacity):
    """只计算摘要、nonce 和消息本身，不计算 Python 对象开销。"""
    digest_storage = (2 * capacity - 1) * 32
    nonce_storage = len(messages) * 32
    return digest_storage + nonce_storage + sum(map(len, messages))


def benchmark(repetitions):
    output = {
        'environment': environment(),
        'repetitions': repetitions,
        'method': '一次预热；perf_counter_ns；均值和标准差；不含内存追踪',
        'tree': [],
        'hash': [],
        'message_length': [],
    }

    for message_length in (0, 32, 135, 136, 137, 273, 4096):
        message = b'a' * message_length
        output['hash'].append({
            'message_bytes': message_length,
            'permutations': message_length // RATE_BYTES + 1,
            'hash': measured(
                lambda: sha3_256_digest(message),
                repetitions,
                batch=10,
            ),
        })

    tree_sizes = (1, 3, 8, 32, 128, 256, 257, 512, 513, 1024, 1025)
    for leaf_count in tree_sizes:
        messages = [
            index.to_bytes(8, 'big') + b'x' * 24
            for index in range(leaf_count)
        ]
        depth = (leaf_count - 1).bit_length()
        capacity = 1 << depth
        commit_timing = measured(
            lambda: tree_module.commit(messages),
            repetitions,
        )

        commitment, tree = tree_module.commit(messages)
        index = leaf_count // 2
        message, proof = tree.open(index)
        proof_bytes = proof.to_bytes()
        commitment_bytes = commitment.to_bytes()
        full_opening = tree.open_all()

        if not tree_module.verify(
            commitment_bytes,
            index,
            message,
            proof_bytes,
        ):
            raise RuntimeError('benchmark single opening failed verification')
        if not tree_module.verify_all(commitment, full_opening):
            raise RuntimeError('benchmark full opening failed verification')

        verify_timing = measured(
            lambda: tree_module.verify(
                commitment_bytes,
                index,
                message,
                proof_bytes,
            ),
            repetitions,
            batch=10,
        )
        full_verify_timing = measured(
            lambda: tree_module.verify_all(commitment, full_opening),
            repetitions,
        )
        hash_work = measure_hash_work(messages)

        output['tree'].append({
            'leaf_count': leaf_count,
            'padded_leaf_count': capacity,
            'depth': depth,
            'hash_calls_observed': hash_work['hash_calls'],
            'permutations_observed': hash_work['permutations'],
            'commitment_bytes': len(commitment_bytes),
            'proof_bytes': len(proof_bytes),
            'full_opening_bytes': len(full_opening.to_bytes()),
            'logical_storage_bytes': logical_storage_bytes(
                messages,
                capacity,
            ),
            'build': commit_timing,
            'verify_wire': verify_timing,
            'verify_full': full_verify_timing,
        })
        print(
            'measured n=%d build=%.3f ms proof=%d B permutations=%d'
            % (
                leaf_count,
                commit_timing['mean_seconds'] * 1e3,
                len(proof_bytes),
                hash_work['permutations'],
            ),
            flush=True,
        )

    for message_length in (0, 32, 78, 79, 4096):
        messages = [b'x' * message_length] * 32
        output['message_length'].append({
            'leaf_count': 32,
            'message_bytes': message_length,
            'build': measured(
                lambda: tree_module.commit(messages),
                repetitions,
            ),
        })

    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path(__file__).resolve().parents[1] / 'results',
    )
    args = parser.parse_args()
    if args.repetitions < 2:
        parser.error('--repetitions must be >= 2')

    data = benchmark(args.repetitions)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.output_dir / 'results.json'
    results_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + '\n'
    )
    print('Saved:', results_path)


if __name__ == '__main__':
    main()
