#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
手动实现的 SHA3-256（Keccak-f[1600] 置换 + SHA-3 填充）。

对外接口：sha3_256_digest(message) -> 32 字节；sha3_256(message) -> 十六进制。
Merkle Tree 的实现在 merkle_tree.py。
"""

# Keccak-f[1600] 的轮常数
ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

MASK = (1 << 64) - 1

def _rotl64(x, n):
    """64 位循环左移"""
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK

def _keccak_f1600(state):
    """Keccak-f[1600] 置换，state 是 5x5 的 64-bit 整数矩阵"""
    for rnd in range(24):
        # θ 步骤
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rotl64(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # ρ 步骤 + π 步骤
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rotl64(
                    state[x][y], ROTATION_OFFSETS[x][y]
                )

        # χ 步骤
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ (
                    (~B[(x + 1) % 5][y] & MASK) & B[(x + 2) % 5][y]
                )

        # ι 步骤
        state[0][0] ^= ROUND_CONSTANTS[rnd]

    return state

def _bytes_to_lanes(data):
    """将字节串按小端序转成 64-bit lane 列表"""
    lanes = []
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        lane = int.from_bytes(chunk, byteorder='little')
        lanes.append(lane)
    return lanes

def _lanes_to_state(lanes):
    """将 lane 列表填入 5x5 state（Keccak 的填充顺序）"""
    state = [[0] * 5 for _ in range(5)]
    for i, lane in enumerate(lanes):
        x = i % 5
        y = i // 5
        state[x][y] = lane & MASK
    return state

def _state_to_bytes(state):
    """将 state 按 Keccak 顺序和小端序展开为字节串"""
    out = bytearray()
    for y in range(5):
        for x in range(5):
            out += state[x][y].to_bytes(8, byteorder='little')
    return bytes(out)

def sha3_256_digest(message: bytes) -> bytes:
    """
    手动实现 FIPS 202 SHA3-256，后缀 0x06；不是 Keccak-256。
    输入: bytes
    输出: 32 字节摘要
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    if not isinstance(message, bytes):
        raise TypeError('message must be bytes or str')

    RATE = 136          # SHA3-256 的 rate = 1088 bits = 136 bytes
    OUTPUT_LEN = 32     # 256 bits

    # ---- 填充 (pad10*1, SHA3 域分隔符 0x06) ----
    padded = bytearray(message)
    padded.append(0x06)
    while len(padded) % RATE != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    # ---- 初始化 state ----
    state = [[0] * 5 for _ in range(5)]

    # ---- Absorb 阶段 ----
    for block_start in range(0, len(padded), RATE):
        block = padded[block_start:block_start + RATE]
        lanes = _bytes_to_lanes(block)
        for i, lane in enumerate(lanes):
            x = i % 5
            y = i // 5
            state[x][y] ^= lane & MASK
        _keccak_f1600(state)

    # ---- Squeeze 阶段 ----
    output = bytearray()
    while len(output) < OUTPUT_LEN:
        block_bytes = _state_to_bytes(state)
        output += block_bytes[:RATE]
        if len(output) < OUTPUT_LEN:
            _keccak_f1600(state)

    return bytes(output[:OUTPUT_LEN])


def sha3_256(message: bytes) -> str:
    """十六进制展示接口，建树使用原始摘要接口。"""
    return sha3_256_digest(message).hex()


# ============================================================
# 自检：固定已知答案；运行时不调用已有哈希实现
# ============================================================
if __name__ == '__main__':
    vectors = [
        (b'', 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'),
        (b'abc', '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'),
    ]
    print("=== SHA3-256 自检 ===")
    for t, ref in vectors:
        mine = sha3_256(t)
        assert mine == ref, (t, mine, ref)
        print(f'input={t!r} PASS')
