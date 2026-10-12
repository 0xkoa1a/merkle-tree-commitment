"""
手写 SHA3-256：把消息按块混入状态，再取出 32 字节摘要。

对外接口：sha3_256_digest(message) -> 32 字节；sha3_256(message) -> 十六进制。
"""

# Keccak-f[1600] 的旋转偏移和轮常数
ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
]

LANE_MASK = (1 << 64) - 1
RATE_BYTES = 136
DIGEST_BYTES = 32


def _rotl64(value: int, shift: int) -> int:
    """把 64 位整数左移 shift 位，移出的位从右边绕回来。"""
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & LANE_MASK


def _keccak_f1600(state: list[list[int]]) -> None:
    """原地进行 24 轮混合；state 有 5 列、5 行，每格是 64 位整数。"""
    for round_index in range(24):
        # θ：先求各列的异或值，再把相邻两列的信息混入当前列。
        column_xors = [
            state[x][0]
            ^ state[x][1]
            ^ state[x][2]
            ^ state[x][3]
            ^ state[x][4]
            for x in range(5)
        ]
        theta_mix = [
            column_xors[(x - 1) % 5]
            ^ _rotl64(column_xors[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= theta_mix[x]

        # ρ + π：先循环移动格子里的位，再把整个格子移到新位置。
        rotated = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                rotated[y][(2 * x + 3 * y) % 5] = _rotl64(
                    state[x][y],
                    ROTATION_OFFSETS[x][y],
                )

        # χ：用右边两个格子的位，决定当前格子哪些位要翻转。
        for x in range(5):
            for y in range(5):
                state[x][y] = rotated[x][y] ^ (
                    (~rotated[(x + 1) % 5][y] & LANE_MASK)
                    & rotated[(x + 2) % 5][y]
                )

        # ι：把本轮常数异或到 (0, 0) 格子。
        state[0][0] ^= ROUND_CONSTANTS[round_index]


def _bytes_to_lanes(data: bytes) -> list[int]:
    """每 8 字节组成一个 64 位整数，先读到的字节放在整数低位。"""
    lanes = []
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        lane = int.from_bytes(chunk, byteorder='little')
        lanes.append(lane)
    return lanes


def _state_to_bytes(state: list[list[int]]) -> bytes:
    """按吸收消息时的格子顺序写回字节，每格先写低位字节。"""
    out = bytearray()
    # 格子编号是 x + 5*y：先写一行中的 5 个格子，再写下一行。
    for y in range(5):
        for x in range(5):
            out += state[x][y].to_bytes(8, byteorder='little')
    return bytes(out)


def sha3_256_digest(message: bytes) -> bytes:
    """返回字节消息的 32 字节 SHA3-256 摘要。"""
    if not isinstance(message, bytes):
        raise TypeError('message must be bytes')

    # 0x06 是 SHA3 的消息后缀；补零到整块，再把末字节的最高位设为 1。
    # 若块内的消息占了 135 字节，0x06 正好填在块末，与 0x80 合成 0x86。
    padded = bytearray(message)
    padded.append(0x06)
    while len(padded) % RATE_BYTES != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    # 状态共 25 个格子，每格 64 位，初始全为零。
    state = [[0] * 5 for _ in range(5)]

    # 每块 136 字节依次异或到状态中，随后执行 24 轮混合。
    for block_start in range(0, len(padded), RATE_BYTES):
        block = padded[block_start:block_start + RATE_BYTES]
        lanes = _bytes_to_lanes(block)
        for i, lane in enumerate(lanes):
            # state[x][y] 的编号为 x + 5*y，与输出时的顺序一致。
            x = i % 5
            y = i // 5
            state[x][y] ^= lane
        _keccak_f1600(state)

    # SHA3-256 只取前 32 字节，当前状态已包含完整摘要。
    return _state_to_bytes(state)[:DIGEST_BYTES]


def sha3_256(message: bytes) -> str:
    """将同一个摘要写成十六进制字符串，方便打印。"""
    return sha3_256_digest(message).hex()
