"""把一组消息做成承诺，再用开封信息重算并核对承诺。"""

from secrets import token_bytes
from typing import Iterable, Tuple, Union

from .sha3 import sha3_256_digest as H
from .protocol import (
    BatchProof,
    Commitment,
    FullOpening,
    SingleProof,
    Message,
    NONCE_BYTES,
    encode_u64,
    message_bytes,
    validate_leaf_count,
    validate_indices,
    validate_u64,
)

# 前缀让四种哈希输入各有一个明确的类型。
LEAF_TAG = b'\x00'
PARENT_TAG = b'\x01'
PADDING_TAG = b'\x02'
COMMITMENT_TAG = b'\x03'


def tree_depth(leaf_count: int) -> int:
    """返回补齐到二次幂后的认证路径层数。"""
    validate_leaf_count(leaf_count)
    return (leaf_count - 1).bit_length()


def _leaf_hash(n: int, index: int, message: bytes, nonce: bytes) -> bytes:
    # 记录数量、位置和消息长度，让同一段字节只有一种解释。
    return H(
        LEAF_TAG
        + encode_u64(n)
        + encode_u64(index)
        + encode_u64(len(message))
        + message
        + nonce
    )


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return H(PARENT_TAG + left + right)


def _levels(
    messages: Tuple[bytes, ...],
    nonces: Tuple[bytes, ...],
) -> Tuple[Tuple[bytes, ...], ...]:
    """生成逐层的哈希值：第 0 层放真实叶和占位叶；之后每层两两合并到树根。"""
    n = len(messages)
    capacity = 1 << tree_depth(n)
    leaves = [
        _leaf_hash(n, i, value, nonces[i])
        for i, value in enumerate(messages)
    ]
    # 不够的位置填占位叶，使每层都能两两配对。
    leaves.extend(
        H(PADDING_TAG + encode_u64(n) + encode_u64(i)) for i in range(n, capacity)
    )
    levels = [tuple(leaves)]
    while len(levels[-1]) > 1:
        level = levels[-1]
        levels.append(tuple(
            _parent_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ))
    return tuple(levels)


def _commitment_hash(n: int, tree_root: bytes) -> bytes:
    """把真实叶子数量和树根一起哈希，得到最终承诺摘要。"""
    return H(COMMITMENT_TAG + encode_u64(n) + tree_root)


def _next_positions(positions):
    """返回本层缺少的兄弟和下一层父位置，两者均按位置递增排列。"""
    known = set(positions)
    needed = sorted({position ^ 1 for position in positions} - known)
    parents = sorted({position // 2 for position in positions})
    return needed, parents


class MerkleTree:
    """承诺方保存的消息、随机值和各层摘要，用来生成开封。"""

    def __init__(self, messages: Iterable[Message]) -> None:
        if isinstance(messages, (str, bytes)):
            raise TypeError('expected a sequence of messages, not one string')
        
        self._messages = tuple(message_bytes(value) for value in messages)
        leaf_count = len(self._messages)
        validate_leaf_count(leaf_count)

        # 每个位置单独生成随机值，开封时只交出这个位置的随机值。
        self._nonces = tuple(token_bytes(NONCE_BYTES) for _ in self._messages)

        self._levels = _levels(self._messages, self._nonces)
        tree_root = self._levels[-1][0]

        self.commitment = Commitment(
            leaf_count=leaf_count,
            digest=_commitment_hash(leaf_count, tree_root),
        )

    def prove(self, index: int) -> SingleProof:
        """按从叶子到根的顺序，收集这个位置的兄弟摘要。"""
        validate_u64(index)
        if index >= len(self._messages):
            raise ValueError('index outside committed vector')
        
        position = index
        siblings = []
        for level in self._levels[:-1]:
            # 同层相邻两个节点是一对：0 和 1、2 和 3……
            # 翻转最低位找到兄弟，除以 2 则得到父节点的位置。
            siblings.append(level[position ^ 1])
            position //= 2

        return SingleProof(
            index=index,
            nonce=self._nonces[index],
            siblings=tuple(siblings),
        )

    def prove_many(self, indices: Iterable[int]) -> BatchProof:
        """逐层收集缺少的兄弟；共同父节点只进入下一层一次，不执行哈希。"""
        indices = tuple(indices)
        validate_indices(indices)
        if indices[-1] >= len(self._messages):
            raise ValueError('index outside committed vector')
        active_positions, siblings = indices, []
        for level in self._levels[:-1]:
            needed, parents = _next_positions(active_positions)
            siblings.extend(level[position] for position in needed)
            active_positions = parents
        return BatchProof(
            indices=indices,
            nonces=tuple(self._nonces[index] for index in indices),
            siblings=tuple(siblings),
        )

    def open(self, index: int) -> Tuple[bytes, SingleProof]:
        """返回消息字节和证明；索引超出范围时抛出 ValueError。"""
        proof = self.prove(index)
        return self._messages[index], proof

    def open_all(self) -> FullOpening:
        """交出全部非占位叶子的消息和随机值，供验证者重建整棵树。"""
        return FullOpening(
            messages=self._messages,
            nonces=self._nonces,
        )

    def open_many(self, indices: Iterable[int]) -> Tuple[Tuple[bytes, ...], BatchProof]:
        """按严格递增位置返回消息元组与共享证明；输入迭代器只消费一次。"""
        proof = self.prove_many(indices)
        messages = tuple(self._messages[index] for index in proof.indices)
        return messages, proof


def commit(messages: Iterable[Message]) -> Tuple[Commitment, MerkleTree]:
    """返回公开承诺和承诺方的树状态；输入应为非空消息列表或迭代器。"""
    tree = MerkleTree(messages)
    return tree.commitment, tree


def verify(
    commitment: Union[Commitment, bytes],
    index: int,
    message: Message,
    proof: Union[SingleProof, bytes],
) -> bool:
    """用之前保存的承诺，检查指定位置的消息。

    承诺和证明可以传对象，也可以传编码后的字节。
    消息和位置都匹配时返回 True；不匹配或格式不对时返回 False。
    """
    try:
        if isinstance(commitment, bytes):
            commitment = Commitment.from_bytes(commitment)
        if isinstance(proof, bytes):
            proof = SingleProof.from_bytes(proof)
        if not isinstance(commitment, Commitment):
            return False
        if not isinstance(proof, SingleProof):
            return False
        validate_u64(index)

        if index != proof.index or index >= commitment.leaf_count:
            return False
        if len(proof.siblings) != tree_depth(commitment.leaf_count):
            return False
        
        current = _leaf_hash(
            commitment.leaf_count,
            index,
            message_bytes(message),
            proof.nonce,
        )

        position = index
        for sibling in proof.siblings:
            # 奇数位置是右孩子，兄弟放左边；偶数位置则相反。
            if position & 1:
                current = _parent_hash(sibling, current)
            else:
                current = _parent_hash(current, sibling)
            position //= 2
        return _commitment_hash(commitment.leaf_count, current) == commitment.digest
    
    except (TypeError, ValueError):
        return False


def verify_many(
    commitment: Union[Commitment, bytes],
    indices: Iterable[int],
    messages: Iterable[Message],
    proof: Union[BatchProof, bytes],
) -> bool:
    """检查期望位置与批量消息，逐层共享合并，恰好消费全部兄弟摘要。

    对象和字节入口一致；每层只保存当前节点，不重复验证独立路径。
    无法匹配位置、消息、证明结构或最终承诺时返回 False。
    """
    try:
        if isinstance(commitment, bytes):
            commitment = Commitment.from_bytes(commitment)
        if isinstance(proof, bytes):
            proof = BatchProof.from_bytes(proof)
        if not isinstance(commitment, Commitment) or not isinstance(proof, BatchProof):
            return False
        indices = tuple(indices)
        validate_indices(indices)
        if indices != proof.indices or indices[-1] >= commitment.leaf_count:
            return False
        if isinstance(messages, (str, bytes)):
            return False
        messages = tuple(message_bytes(value) for value in messages)
        if len(messages) != len(indices):
            return False
        n = commitment.leaf_count
        current_nodes = {
            index: _leaf_hash(n, index, message, nonce)
            for index, message, nonce in zip(indices, messages, proof.nonces)
        }
        cursor = 0
        for _ in range(tree_depth(n)):
            needed, parents = _next_positions(current_nodes)
            for position in needed:
                if cursor == len(proof.siblings):
                    return False
                current_nodes[position] = proof.siblings[cursor]
                cursor += 1
            current_nodes = {
                parent: _parent_hash(current_nodes[2 * parent], current_nodes[2 * parent + 1])
                for parent in parents
            }
        if cursor != len(proof.siblings):
            return False
        return _commitment_hash(n, current_nodes[0]) == commitment.digest
    except (TypeError, ValueError):
        return False


def verify_all(
    commitment: Union[Commitment, bytes],
    opening: Union[FullOpening, bytes],
) -> bool:
    """按全部消息和随机值重建树，与保存的承诺比较。

    承诺和开封可以传对象或编码字节；不匹配或格式不对时返回 False。
    """
    try:
        if isinstance(commitment, bytes):
            commitment = Commitment.from_bytes(commitment)
        if isinstance(opening, bytes):
            opening = FullOpening.from_bytes(opening)
        if not isinstance(commitment, Commitment):
            return False
        if not isinstance(opening, FullOpening):
            return False
        if len(opening.messages) != commitment.leaf_count:
            return False
        
        tree_root = _levels(opening.messages, opening.nonces)[-1][0]
        return _commitment_hash(commitment.leaf_count, tree_root) == commitment.digest
    
    except (TypeError, ValueError):
        return False
