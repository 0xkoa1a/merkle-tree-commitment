#!/usr/bin/env python3
"""作业验证入口：正确性、安全回归、猜测演示和性能评估。"""
import argparse
from datetime import datetime
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import tracemalloc
import unittest

import merkle_tree as m
from privacy_experiment import run as privacy_run
from sha3 import sha3_256_digest
import test_scheme


def environment():
    def sysctl(key):
        try:
            return subprocess.check_output(['sysctl', '-n', key], text=True,
                                           stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            return 'unavailable'
    cpu = sysctl('machdep.cpu.brand_string')
    return {'python': sys.version, 'system': platform.system(),
            'os_release': platform.release(), 'machine': platform.machine(),
            'processor': cpu if cpu != 'unavailable' else (platform.processor() or 'unavailable'),
            'logical_cpus': sysctl('hw.logicalcpu'), 'memory_bytes': sysctl('hw.memsize'),
            'executable': sys.executable, 'timestamp': datetime.now().astimezone().isoformat()}


def measured(fn, repetitions, batch=1):
    fn()  # 一次预热，不进入样本。
    samples = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        for _ in range(batch):
            fn()
        samples.append((time.perf_counter_ns() - started) / batch / 1e9)
    return {'samples_seconds': samples, 'mean_seconds': statistics.mean(samples),
            'median_seconds': statistics.median(samples),
            'stdev_seconds': statistics.stdev(samples) if repetitions > 1 else 0.0,
            'min_seconds': min(samples), 'max_seconds': max(samples), 'batch': batch}


def benchmark(repetitions):
    output = {'environment': environment(), 'repetitions': repetitions,
              'method': '一次预热；perf_counter_ns；计时不含tracemalloc；单独测建树峰值Python分配',
              'tree': [], 'hash': [], 'message_length': []}
    for length in (0, 32, 135, 136, 137, 273, 4096):
        value = bytes([0x61]) * length
        output['hash'].append({'message_bytes': length,
                               'permutations': length // 136 + 1,
                               'hash': measured(lambda: sha3_256_digest(value), repetitions, batch=10)})
    for n in (1, 3, 8, 32, 128, 256, 1024):
        values = [i.to_bytes(8, 'big') + b'x' * 24 for i in range(n)]
        depth, capacity = (n - 1).bit_length(), 1 << (n - 1).bit_length()
        build = measured(lambda: m.commit(values), repetitions)
        public, state = m.commit(values)
        index = n // 2
        value, proof = state.open(index)
        wire, public_wire = proof.to_bytes(), public.to_bytes()
        opening = state.open_all()
        assert m.verify(public_wire, index, value, wire)
        assert m.verify_all(public, opening)
        generate = measured(lambda: state.prove(index), repetitions, batch=200)
        verify = measured(lambda: m.verify(public_wire, index, value, wire), repetitions, batch=10)
        full_verify = measured(lambda: m.verify_all(public, opening), repetitions)
        serialize = measured(proof.to_bytes, repetitions, batch=200)
        # 临时计数器确认实现调用次数，计数不进入任何延迟样本。
        original, counter = m.H, [0]
        def counted(data):
            counter[0] += 1
            return original(data)
        m.H = counted
        try:
            m.commit(values)
        finally:
            m.H = original
        assert counter[0] == 2 * capacity
        tracemalloc.start()
        memory_state = m.commit(values)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        del memory_state
        output['tree'].append({'leaf_count': n, 'message_bytes': 32, 'depth': depth,
            'padded_leaf_count': capacity, 'hash_calls_observed': counter[0],
            'commitment_bytes': len(public_wire), 'proof_bytes': len(wire),
            'full_opening_bytes': len(opening.to_bytes()), 'python_peak_bytes': peak,
            'build': build, 'prove': generate, 'verify_wire': verify,
            'verify_full': full_verify, 'proof_serialization': serialize,
            'leaves_per_second': n / build['mean_seconds']})
        print('measured n=%d build=%.3f ms proof=%d B' %
              (n, build['mean_seconds'] * 1e3, len(wire)), flush=True)
    for length in (0, 32, 256, 4096):
        values = [b'x' * length] * 32
        output['message_length'].append({'leaf_count': 32, 'message_bytes': length,
            'build': measured(lambda: m.commit(values), repetitions)})
    return output


def render_report(data, test_count):
    env = data['environment']
    lines = ['# 性能与验证结果', '', '由 `python3 test2.py --repetitions %d` 自动生成。' % data['repetitions'], '',
             '## 环境与测量边界', '',
             '- 时间：' + env['timestamp'], '- Python：' + env['python'].replace('\n', ' '),
             '- 设备：%s / %s / %s / %s' % (env['system'], env['os_release'], env['machine'], env['processor']),
             '- 逻辑 CPU：%s；内存字节：%s。' % (env['logical_cpus'], env['memory_bytes']),
             '- 硬件记录：' + env.get('hardware_source', '基准启动时只读查询；不支持或受限的字段标为 unavailable。'),
             '- %d 项 unittest 通过；低熵攻击演示结果另见原始 JSON。' % test_count,
             '- 每项一次预热、%d 组样本；表格报告均值及样本标准差。原始样本保存在 results.json。' % data['repetitions'],
             '- 建树计时包含消息规范化、操作系统随机值生成、哈希及树分配。',
             '- 单项验证计时包含承诺/证明解析及根比较，消息由调用方提供。',
             '- 峰值是单独运行 tracemalloc 得到的 Python 分配峰值，不是进程 RSS；其开销未混入计时。',
             '- 单项证明测索引 n//2；每层方向由索引确定，无单独方向字段。', '',
             '## 建树与单项开封', '',
             '| n | 补齐叶数 | 实测哈希次数 | 建树 ms | 吞吐 leaves/s | 生成 μs | 验证 ms | 证明 B | Python 峰值 KiB |',
             '| --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for row in data['tree']:
        lines.append('| %d | %d | %d | %.3f ± %.3f | %.0f | %.3f ± %.3f | %.3f ± %.3f | %d | %.1f |' %
            (row['leaf_count'], row['padded_leaf_count'], row['hash_calls_observed'],
             row['build']['mean_seconds'] * 1e3, row['build']['stdev_seconds'] * 1e3,
             row['leaves_per_second'], row['prove']['mean_seconds'] * 1e6,
             row['prove']['stdev_seconds'] * 1e6,
             row['verify_wire']['mean_seconds'] * 1e3, row['verify_wire']['stdev_seconds'] * 1e3,
             row['proof_bytes'], row['python_peak_bytes'] / 1024))
    lines += ['', '所有承诺编码均为 41 B；单项证明实际编码为 43 + 32h B，h 为补齐树深度。消息内容不含在这个证明大小中。',
              '补齐后的叶数 N 满足 n ≤ N < 2n，建树调用哈希 2N 次（包括占位叶和最终数量绑定），因此为 O(n)。',
              '单项验证调用 h+2 次哈希；生成证明仅取兄弟摘要，为 O(log n)。这些次数不等同于 Keccak 置换次数，长消息一次哈希可以有多次置换。', '',
              '## 完整开封及证明序列化', '',
              '| n | 完整开封 B | 完整验证 ms | 单项证明序列化 μs |', '| --- | --- | --- | --- |']
    for row in data['tree']:
        lines.append('| %d | %d | %.3f ± %.3f | %.3f ± %.3f |' % (row['leaf_count'], row['full_opening_bytes'],
                     row['verify_full']['mean_seconds'] * 1e3,
                     row['verify_full']['stdev_seconds'] * 1e3,
                     row['proof_serialization']['mean_seconds'] * 1e6,
                     row['proof_serialization']['stdev_seconds'] * 1e6))
    lines += ['', '## 手写 SHA3-256', '', '| 输入 B | 置换次数 | 哈希 ms（均值 ± 标准差） |', '| --- | --- | --- |']
    for row in data['hash']:
        lines.append('| %d | %d | %.3f ± %.3f |' % (row['message_bytes'], row['permutations'],
            row['hash']['mean_seconds'] * 1e3, row['hash']['stdev_seconds'] * 1e3))
    lines += ['', '## 消息长度对建树的影响', '', '| n | 每叶消息 B | 建树 ms（均值 ± 标准差） |', '| --- | --- | --- |']
    for row in data['message_length']:
        lines.append('| %d | %d | %.3f ± %.3f |' % (row['leaf_count'], row['message_bytes'],
                     row['build']['mean_seconds'] * 1e3, row['build']['stdev_seconds'] * 1e3))
    lines += ['', '## 结果解释', '',
              '建树工作量随补齐叶数线性增长；跨越 2 的幂时，占位叶会增加实际工作量。',
              '证明大小由实际序列化测得，随深度每增加一级增长 32 B。长消息增加叶子哈希吸收的块数，影响建树和验证时间。',
              '所有时间都是该设备上纯 Python 实现的实测值；微秒级生成时间会受调度和计时开销影响，跨设备比较应重新运行。', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--tests-only', action='store_true')
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).with_name('results'))
    args = parser.parse_args()
    if args.repetitions < 2:
        parser.error('--repetitions must be >= 2')
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_scheme)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    privacy = privacy_run()
    print(json.dumps(privacy, ensure_ascii=False, indent=2), flush=True)
    if args.tests_only:
        return
    data = benchmark(args.repetitions)
    data['verification'] = {'unittest_count': result.testsRun, 'passed': True, 'privacy': privacy}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / 'results.json').write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
    (args.output_dir / '性能与验证结果.md').write_text(render_report(data, result.testsRun))
    print('Saved:', args.output_dir)


if __name__ == '__main__':
    main()
