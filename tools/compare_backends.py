"""独立工具：固定规模比较 Python/C，只写一份 JSON，不参与实验主入口。

PYTHONPATH=src .venv/bin/python -B tools/compare_backends.py
#! n=1024、消息 32 B、k=64 个固定位置；五组、每组目标 0.2 s。
不扫描长度或规模；复用 performance.measure，数据制备与计数不进入计时。
默认输出 all-outputs/backend-comparison/jsons/backend-comparison.json，独立于规模实验。
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # 导入既有实验计时工具，不复制一套计时器。


def measure_backend():
    """两端制备证明的输入/nonce/位置一致；计时 commit 沿用生产随机源。"""
    import random
    from unittest.mock import patch
    from merkle_commitment import tree as mt
    from experiments.performance import environment, measure, hash_work

    n, k = 1024, 64
    messages = [i.to_bytes(8, 'big') + b'x' * 24 for i in range(n)]
    indices = tuple(range(128, 128 + k))
    rng = random.Random(20261013)
    # 仅工具制备数据使用固定 nonce；正式 commit 的 secrets 随机源不改动。
    with patch.object(mt, 'token_bytes', lambda size: rng.getrandbits(size * 8).to_bytes(size, 'big')):
        commitment, tree = mt.commit(messages)
    opened, proof = tree.open_many(indices)
    assert mt.verify_many(commitment, indices, opened, proof)
    operations = {
        'commit': lambda: mt.commit(messages),
        'open_many': lambda: tree.open_many(indices),
        'verify_many': lambda: mt.verify_many(commitment, indices, opened, proof),
    }
    work = {name: hash_work(operation) for name, operation in operations.items()}
    return {'environment': environment(), 'commitment_hex': commitment.digest.hex(),
            'parameters': {'n': n, 'message_bytes': 32, 'k': k, 'indices': indices,
                           'groups': 5, 'calibration_target_seconds': 0.2},
            'work': work,
            'timings': {name: measure(operation, quick=False, groups=5)
                        for name, operation in operations.items()}}


def main():
    """分进程绑定两个后端；任何 C 加载失败直接报错，不改用 Python。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'all-outputs/backend-comparison/jsons/backend-comparison.json')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(measure_backend(), ensure_ascii=False))
        return

    # 先检查 C 可加载，避免先跑完 Python 才发现未构建。
    from merkle_commitment import _sha3_c

    results = {}
    for backend in ('python', 'c'):
        env = dict(os.environ, MTC_SHA3_BACKEND=backend)
        output = subprocess.check_output(
            [sys.executable, '-B', str(Path(__file__).resolve()), '--worker'], env=env, text=True,
        )
        results[backend] = json.loads(output)
        print(f'{backend}: fixed-scale measurement complete', flush=True)
    assert results['python']['commitment_hex'] == results['c']['commitment_hex']
    assert results['python']['work'] == results['c']['work']
    ratios = {name: results['python']['timings'][name]['median_seconds']
                    / results['c']['timings'][name]['median_seconds']
              for name in results['python']['timings']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'backends': results, 'python_over_c': ratios},
                                     ensure_ascii=False, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()
