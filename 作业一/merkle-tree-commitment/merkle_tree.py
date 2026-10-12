#!/usr/bin/env python3
"""随机化 Merkle 向量承诺；哈希与树算法均在本项目实现。"""

from dataclasses import dataclass
from secrets import token_bytes
from typing import Tuple

from sha3 import sha3_256_digest as H

VERSION = 1
HASH_BYTES = 32
NONCE_BYTES = 32
MAX_U64 = (1 << 64) - 1


def _u64(value):
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError('expected an unsigned 64-bit integer')
    return value.to_bytes(8, 'big')


def _message(value):
    if isinstance(value, str):
        return value.encode('utf-8')
    if type(value) is not bytes:
        raise TypeError('message must be bytes or UTF-8 str')
    return value


def _digest(value):
    if type(value) is not bytes or len(value) != HASH_BYTES:
        raise ValueError('digest must be exactly 32 bytes')


def _nonce(value):
    if type(value) is not bytes or len(value) != NONCE_BYTES:
        raise ValueError('opening randomness must be exactly 32 bytes')


def _depth(n):
    _u64(n)
    if n == 0:
        raise ValueError('empty vectors are not supported')
    return (n - 1).bit_length()


def _leaf_hash(n, index, message, nonce):
    # 定长 n/index/length 和 nonce 使编码可以唯一解析。
    return H(b'\x00' + _u64(n) + _u64(index)
             + _u64(len(message)) + message + nonce)


def _parent_hash(left, right):
    return H(b'\x01' + left + right)


def _levels(messages, nonces):
    n = len(messages)
    capacity = 1 << _depth(n)
    leaves = [_leaf_hash(n, i, value, nonces[i])
              for i, value in enumerate(messages)]
    # 补齐到 2 的幂，使用专门类型的占位叶，绝不复制真实末叶。
    leaves.extend(H(b'\x02' + _u64(n) + _u64(i))
                  for i in range(n, capacity))
    levels = [tuple(leaves)]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append(tuple(_parent_hash(row[i], row[i + 1])
                            for i in range(0, len(row), 2)))
    return tuple(levels)


def _root_hash(n, tree_root):
    return H(b'\x03' + _u64(n) + tree_root)


@dataclass(frozen=True)
class Commitment:
    """公开承诺：数量与最终摘要。版本由固定协议和编码限定。"""
    leaf_count: int
    root: bytes

    def __post_init__(self):
        _depth(self.leaf_count)
        _digest(self.root)

    def to_bytes(self):
        return bytes([VERSION]) + _u64(self.leaf_count) + self.root

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) != 41 or data[0] != VERSION:
            raise ValueError('invalid commitment encoding')
        return cls(int.from_bytes(data[1:9], 'big'), data[9:])


@dataclass(frozen=True)
class MerkleProof:
    """开封位置、该位置的随机值及由叶到根的兄弟摘要。"""
    index: int
    nonce: bytes
    siblings: Tuple[bytes, ...]

    def __post_init__(self):
        _u64(self.index)
        _nonce(self.nonce)
        if type(self.siblings) is not tuple or len(self.siblings) > 64:
            raise ValueError('siblings must be a tuple of at most 64 digests')
        for sibling in self.siblings:
            _digest(sibling)

    def to_bytes(self):
        return (bytes([VERSION]) + _u64(self.index) + self.nonce
                + len(self.siblings).to_bytes(2, 'big') + b''.join(self.siblings))

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) < 43 or data[0] != VERSION:
            raise ValueError('invalid proof encoding')
        depth = int.from_bytes(data[41:43], 'big')
        if depth > 64 or len(data) != 43 + HASH_BYTES * depth:
            raise ValueError('invalid proof length')
        return cls(int.from_bytes(data[1:9], 'big'), data[9:41],
                   tuple(data[i:i + HASH_BYTES] for i in range(43, len(data), HASH_BYTES)))


@dataclass(frozen=True)
class FullOpening:
    """完整开封，主动公开所有消息和所有随机值。"""
    messages: Tuple[bytes, ...]
    nonces: Tuple[bytes, ...]

    def __post_init__(self):
        if type(self.messages) is not tuple or type(self.nonces) is not tuple:
            raise ValueError('full opening requires immutable tuples')
        _depth(len(self.messages))
        if len(self.messages) != len(self.nonces):
            raise ValueError('message/nonce counts differ')
        for value in self.messages:
            if type(value) is not bytes:
                raise TypeError('encoded messages must be bytes')
            _u64(len(value))
        for nonce in self.nonces:
            _nonce(nonce)

    def to_bytes(self):
        return (bytes([VERSION]) + _u64(len(self.messages))
                + b''.join(_u64(len(m)) + m + r
                           for m, r in zip(self.messages, self.nonces)))

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) < 9 or data[0] != VERSION:
            raise ValueError('invalid full opening encoding')
        n = int.from_bytes(data[1:9], 'big')
        if n == 0 or n > (len(data) - 9) // 40:
            raise ValueError('invalid full opening count')
        messages, nonces, offset = [], [], 9
        for _ in range(n):
            if offset + 8 > len(data):
                raise ValueError('truncated message length')
            length = int.from_bytes(data[offset:offset + 8], 'big')
            offset += 8
            end = offset + length
            if end + NONCE_BYTES > len(data):
                raise ValueError('truncated message or nonce')
            messages.append(data[offset:end])
            nonces.append(data[end:end + NONCE_BYTES])
            offset = end + NONCE_BYTES
        if offset != len(data):
            raise ValueError('trailing full opening bytes')
        return cls(tuple(messages), tuple(nonces))


class MerkleTree:
    """Commit 的私有状态。每次创建都生成新的独立随机值。"""

    def __init__(self, messages):
        if isinstance(messages, (str, bytes)):
            raise TypeError('expected a sequence of messages, not one string')
        self._messages = tuple(_message(value) for value in messages)
        _depth(len(self._messages))
        self._nonces = tuple(token_bytes(NONCE_BYTES) for _ in self._messages)
        self._levels = _levels(self._messages, self._nonces)
        self.commitment = Commitment(len(self._messages),
                                      _root_hash(len(self._messages), self._levels[-1][0]))

    def prove(self, index):
        _u64(index)
        if index >= len(self._messages):
            raise ValueError('index outside committed vector')
        position, siblings = index, []
        for row in self._levels[:-1]:
            siblings.append(row[position ^ 1])
            position //= 2
        return MerkleProof(index, self._nonces[index], tuple(siblings))

    def open(self, index):
        proof = self.prove(index)
        return self._messages[index], proof

    def open_all(self):
        return FullOpening(self._messages, self._nonces)


def commit(messages):
    """返回 (公开承诺, 私有状态)，私有状态由承诺方保管。"""
    tree = MerkleTree(messages)
    return tree.commitment, tree


def verify(commitment, index, message, proof):
    """独立验证指定位置；无需建树状态或其它叶子的随机值。

    commitment 必须来自验证者此前保存的可信承诺；index 是验证者期望的位置。
    畸形证明返回 False；解析器本身则抛 ValueError。
    """
    try:
        if type(commitment) is bytes:
            commitment = Commitment.from_bytes(commitment)
        if type(proof) is bytes:
            proof = MerkleProof.from_bytes(proof)
        if type(commitment) is not Commitment or type(proof) is not MerkleProof:
            return False
        _u64(index)
        if index != proof.index or index >= commitment.leaf_count:
            return False
        if len(proof.siblings) != _depth(commitment.leaf_count):
            return False
        current = _leaf_hash(commitment.leaf_count, index, _message(message), proof.nonce)
        position = index
        for sibling in proof.siblings:
            current = (_parent_hash(sibling, current) if position & 1
                       else _parent_hash(current, sibling))
            position //= 2
        return _root_hash(commitment.leaf_count, current) == commitment.root
    except (TypeError, ValueError, OverflowError):
        return False


def verify_all(commitment, opening):
    """验证完整向量的开封，包含消息的顺序和数量。"""
    try:
        if type(commitment) is bytes:
            commitment = Commitment.from_bytes(commitment)
        if type(opening) is bytes:
            opening = FullOpening.from_bytes(opening)
        if type(commitment) is not Commitment or type(opening) is not FullOpening:
            return False
        if len(opening.messages) != commitment.leaf_count:
            return False
        tree_root = _levels(opening.messages, opening.nonces)[-1][0]
        return _root_hash(commitment.leaf_count, tree_root) == commitment.root
    except (TypeError, ValueError, OverflowError):
        return False


if __name__ == '__main__':
    public, state = commit(['a', 'b', 'a', '你好'])
    message, proof = state.open(2)
    print('commitment:', public.to_bytes().hex())
    print('proof bytes:', len(proof.to_bytes()))
    print('valid:', verify(public.to_bytes(), 2, message, proof.to_bytes()))
    print('tampered:', verify(public, 2, b'changed', proof))
    print('full opening:', verify_all(public, state.open_all()))
