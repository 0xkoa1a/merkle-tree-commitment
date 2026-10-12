"""协议数据类型、规范编码及输入校验。"""

from dataclasses import dataclass
from typing import Tuple

VERSION = 1
HASH_BYTES = 32
NONCE_BYTES = 32
MAX_U64 = (1 << 64) - 1
VERSION_BYTES = 1
U64_BYTES = 8
DEPTH_BYTES = 2
MAX_PROOF_DEPTH = 64
COMMITMENT_BYTES = VERSION_BYTES + U64_BYTES + HASH_BYTES
PROOF_NONCE_END = VERSION_BYTES + U64_BYTES + NONCE_BYTES
PROOF_HEADER_BYTES = PROOF_NONCE_END + DEPTH_BYTES
FULL_HEADER_BYTES = VERSION_BYTES + U64_BYTES


def encode_u64(value):
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError('expected an unsigned 64-bit integer')
    return value.to_bytes(U64_BYTES, 'big')


def message_bytes(value):
    if isinstance(value, str):
        return value.encode('utf-8')
    if type(value) is not bytes:
        raise TypeError('message must be bytes or UTF-8 str')
    return value


def _fixed_bytes(value, size, field):
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f'{field} must be exactly {size} bytes')


def tree_depth(n):
    encode_u64(n)
    if n == 0:
        raise ValueError('empty vectors are not supported')
    return (n - 1).bit_length()


@dataclass(frozen=True)
class Commitment:
    """公开承诺：数量与最终摘要。版本由固定协议和编码限定。"""
    leaf_count: int
    root: bytes

    def __post_init__(self):
        tree_depth(self.leaf_count)
        _fixed_bytes(self.root, HASH_BYTES, 'digest')

    def to_bytes(self):
        return bytes([VERSION]) + encode_u64(self.leaf_count) + self.root

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) != COMMITMENT_BYTES or data[0] != VERSION:
            raise ValueError('invalid commitment encoding')
        return cls(int.from_bytes(data[VERSION_BYTES:FULL_HEADER_BYTES], 'big'),
                   data[FULL_HEADER_BYTES:])


@dataclass(frozen=True)
class MerkleProof:
    """开封位置、该位置的随机值及由叶到根的兄弟摘要。"""
    index: int
    nonce: bytes
    siblings: Tuple[bytes, ...]

    def __post_init__(self):
        encode_u64(self.index)
        _fixed_bytes(self.nonce, NONCE_BYTES, 'opening randomness')
        if type(self.siblings) is not tuple or len(self.siblings) > MAX_PROOF_DEPTH:
            raise ValueError('siblings must be a tuple of at most 64 digests')
        for sibling in self.siblings:
            _fixed_bytes(sibling, HASH_BYTES, 'digest')

    def to_bytes(self):
        return (bytes([VERSION]) + encode_u64(self.index) + self.nonce
                + len(self.siblings).to_bytes(DEPTH_BYTES, 'big') + b''.join(self.siblings))

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) < PROOF_HEADER_BYTES or data[0] != VERSION:
            raise ValueError('invalid proof encoding')
        depth = int.from_bytes(data[PROOF_NONCE_END:PROOF_HEADER_BYTES], 'big')
        if depth > MAX_PROOF_DEPTH or len(data) != PROOF_HEADER_BYTES + HASH_BYTES * depth:
            raise ValueError('invalid proof length')
        return cls(int.from_bytes(data[VERSION_BYTES:FULL_HEADER_BYTES], 'big'),
                   data[FULL_HEADER_BYTES:PROOF_NONCE_END],
                   tuple(data[i:i + HASH_BYTES] for i in range(PROOF_HEADER_BYTES, len(data), HASH_BYTES)))


@dataclass(frozen=True)
class FullOpening:
    """完整开封，主动公开所有消息和所有随机值。"""
    messages: Tuple[bytes, ...]
    nonces: Tuple[bytes, ...]

    def __post_init__(self):
        if type(self.messages) is not tuple or type(self.nonces) is not tuple:
            raise ValueError('full opening requires immutable tuples')
        tree_depth(len(self.messages))
        if len(self.messages) != len(self.nonces):
            raise ValueError('message/nonce counts differ')
        for value in self.messages:
            if type(value) is not bytes:
                raise TypeError('encoded messages must be bytes')
            encode_u64(len(value))
        for nonce in self.nonces:
            _fixed_bytes(nonce, NONCE_BYTES, 'opening randomness')

    def to_bytes(self):
        return (bytes([VERSION]) + encode_u64(len(self.messages))
                + b''.join(encode_u64(len(m)) + m + r
                           for m, r in zip(self.messages, self.nonces)))

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) < FULL_HEADER_BYTES or data[0] != VERSION:
            raise ValueError('invalid full opening encoding')
        n = int.from_bytes(data[VERSION_BYTES:FULL_HEADER_BYTES], 'big')
        if n == 0 or n > (len(data) - FULL_HEADER_BYTES) // (U64_BYTES + NONCE_BYTES):
            raise ValueError('invalid full opening count')
        messages, nonces, offset = [], [], FULL_HEADER_BYTES
        for _ in range(n):
            if offset + U64_BYTES > len(data):
                raise ValueError('truncated message length')
            length = int.from_bytes(data[offset:offset + U64_BYTES], 'big')
            offset += U64_BYTES
            end = offset + length
            if end + NONCE_BYTES > len(data):
                raise ValueError('truncated message or nonce')
            messages.append(data[offset:end])
            nonces.append(data[end:end + NONCE_BYTES])
            offset = end + NONCE_BYTES
        if offset != len(data):
            raise ValueError('trailing full opening bytes')
        return cls(tuple(messages), tuple(nonces))


