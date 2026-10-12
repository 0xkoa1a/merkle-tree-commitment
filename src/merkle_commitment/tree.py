"""把一组消息做成承诺，再用开封信息重算并核对承诺。"""

from secrets import token_bytes
from typing import Iterable, Tuple, Union

from .sha3 import sha3_256_digest as H
from .protocol import (
    Commitment,
    FullOpening,
    MerkleProof,
    Message,
    NONCE_BYTES,
    encode_u64,
    message_bytes,
    validate_leaf_count,
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


def _root_hash(n: int, tree_root: bytes) -> bytes:
    """把真实叶子数量和树根一起哈希，得到最终承诺摘要。"""
    return H(COMMITMENT_TAG + encode_u64(n) + tree_root)


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
            root=_root_hash(leaf_count, tree_root),
        )

    def prove(self, index: int) -> MerkleProof:
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

        return MerkleProof(
            index=index,
            nonce=self._nonces[index],
            siblings=tuple(siblings),
        )

    # TODO(B-MULTIPROOF): 主逻辑完成后实现 prove_many。
    # active_positions = list(indices)
    # for level in self._levels[:-1]:
    #     known = set(active_positions)
    #     needed = sorted({position ^ 1 for position in known} - known)
    #     append level[position] for every position in needed
    #     active_positions = sorted({position // 2 for position in known})
    # return MultiProof(indices=..., nonces=..., siblings=...)

    def open(self, index: int) -> Tuple[bytes, MerkleProof]:
        """返回消息字节和证明；索引超出范围时抛出 ValueError。"""
        proof = self.prove(index)
        return self._messages[index], proof

    def open_all(self) -> FullOpening:
        """交出全部非占位叶子的消息和随机值，供验证者重建整棵树。"""
        return FullOpening(
            messages=self._messages,
            nonces=self._nonces,
        )


def commit(messages: Iterable[Message]) -> Tuple[Commitment, MerkleTree]:
    """返回公开承诺和承诺方的树状态；输入应为非空消息列表或迭代器。"""
    tree = MerkleTree(messages)
    return tree.commitment, tree


def verify(
    commitment: Union[Commitment, bytes],
    index: int,
    message: Message,
    proof: Union[MerkleProof, bytes],
) -> bool:
    """用之前保存的承诺，检查指定位置的消息。

    承诺和证明可以传对象，也可以传编码后的字节。
    消息和位置都匹配时返回 True；不匹配或格式不对时返回 False。
    """
    try:
        if isinstance(commitment, bytes):
            commitment = Commitment.from_bytes(commitment)
        if isinstance(proof, bytes):
            proof = MerkleProof.from_bytes(proof)
        if not isinstance(commitment, Commitment):
            return False
        if not isinstance(proof, MerkleProof):
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
        return _root_hash(commitment.leaf_count, current) == commitment.root
    
    except (TypeError, ValueError):
        return False


# TODO(B-MULTIPROOF): 主逻辑完成后实现 verify_many。
# 1. 解析 commitment/proof，检查 indices、messages、nonces 数量和范围。
# 2. 由公开消息和 nonce 建立 current_nodes。
# 3. 每层按位置递增遍历，缺兄弟时顺序消费 proof.siblings。
# 4. 每对节点只计算一次父节点，然后进入上一层。
# 5. 兄弟不足或最终仍有剩余都拒绝。
# 6. root_hash(n, current_nodes[0]) 必须等于 commitment.root。


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
        return _root_hash(commitment.leaf_count, tree_root) == commitment.root
    
    except (TypeError, ValueError):
        return False
