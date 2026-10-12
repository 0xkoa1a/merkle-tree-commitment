"""随机化 Merkle 向量承诺的构建、开封和验证。"""

from secrets import token_bytes

from .sha3 import sha3_256_digest as H
from .protocol import (Commitment, FullOpening, MerkleProof, NONCE_BYTES,
                       encode_u64, message_bytes, tree_depth)


def _leaf_hash(n, index, message, nonce):
    # 定长 n/index/length 和 nonce 使编码可以唯一解析。
    return H(b'\x00' + encode_u64(n) + encode_u64(index)
             + encode_u64(len(message)) + message + nonce)


def _parent_hash(left, right):
    return H(b'\x01' + left + right)


def _levels(messages, nonces):
    n = len(messages)
    capacity = 1 << tree_depth(n)
    leaves = [_leaf_hash(n, i, value, nonces[i])
              for i, value in enumerate(messages)]
    # 补齐到 2 的幂，使用专门类型的占位叶，绝不复制真实末叶。
    leaves.extend(H(b'\x02' + encode_u64(n) + encode_u64(i))
                  for i in range(n, capacity))
    levels = [tuple(leaves)]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append(tuple(_parent_hash(row[i], row[i + 1])
                            for i in range(0, len(row), 2)))
    return tuple(levels)


def _root_hash(n, tree_root):
    return H(b'\x03' + encode_u64(n) + tree_root)


class MerkleTree:
    """Commit 的私有状态。每次创建都生成新的独立随机值。"""

    def __init__(self, messages):
        if isinstance(messages, (str, bytes)):
            raise TypeError('expected a sequence of messages, not one string')
        self._messages = tuple(message_bytes(value) for value in messages)
        tree_depth(len(self._messages))
        self._nonces = tuple(token_bytes(NONCE_BYTES) for _ in self._messages)
        self._levels = _levels(self._messages, self._nonces)
        self.commitment = Commitment(len(self._messages),
                                      _root_hash(len(self._messages), self._levels[-1][0]))

    def prove(self, index):
        encode_u64(index)
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
        encode_u64(index)
        if index != proof.index or index >= commitment.leaf_count:
            return False
        if len(proof.siblings) != tree_depth(commitment.leaf_count):
            return False
        current = _leaf_hash(commitment.leaf_count, index, message_bytes(message), proof.nonce)
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
