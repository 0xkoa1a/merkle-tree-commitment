"""定义承诺和开封包含哪些字段，以及怎样把它们读写成字节。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, Union

Message = Union[str, bytes]

VERSION = 1
HASH_BYTES = 32
NONCE_BYTES = 32
MAX_U64 = (1 << 64) - 1
VERSION_BYTES = 1
U64_BYTES = 8
DEPTH_BYTES = 2
# 数量和索引使用 U64，所以合法二叉认证路径最多 64 层。
MAX_PROOF_DEPTH = 64
# 三种编码都先写版本，再写一个 8 字节整数（数量或索引）。
INTEGER_END = VERSION_BYTES + U64_BYTES
COMMITMENT_BYTES = INTEGER_END + HASH_BYTES
PROOF_NONCE_END = INTEGER_END + NONCE_BYTES
PROOF_HEADER_BYTES = PROOF_NONCE_END + DEPTH_BYTES
FULL_HEADER_BYTES = INTEGER_END


def validate_u64(value: int) -> None:
    """检查 value 是能装进 8 字节的非负整数。"""
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError('expected an unsigned 64-bit integer')


def validate_leaf_count(n: int) -> None:
    """叶子数量至少为 1，并且能写进数量字段。"""
    validate_u64(n)
    if n == 0:
        raise ValueError('empty vectors are not supported')


def encode_u64(value: int) -> bytes:
    """把整数写成 8 字节，大端序让高位字节排在前面。"""
    validate_u64(value)
    return value.to_bytes(U64_BYTES, 'big')


def message_bytes(value: Message) -> bytes:
    """字符串先转成 UTF-8 字节；字节消息直接使用。"""
    if isinstance(value, str):
        return value.encode('utf-8')
    if not isinstance(value, bytes):
        raise TypeError('message must be bytes or UTF-8 str')
    return value


def _validate_fixed_bytes(value: bytes, size: int, field: str) -> None:
    """检查字节串是否符合给定的预期长度。"""
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f'{field} must be exactly {size} bytes')


@dataclass(frozen=True)
class Commitment:
    """公开的叶子数量和承诺摘要，供验证者保存和比较。"""
    leaf_count: int
    root: bytes

    def __post_init__(self) -> None:
        validate_leaf_count(self.leaf_count)
        _validate_fixed_bytes(self.root, HASH_BYTES, 'digest')

    def to_bytes(self) -> bytes:
        """依次写入版本、叶子数量和承诺摘要。"""
        return bytes([VERSION]) + encode_u64(self.leaf_count) + self.root

    @classmethod
    def from_bytes(cls, data: bytes) -> Commitment:
        """读回承诺；格式不完整或版本不对时抛出 ValueError。"""
        if (
            not isinstance(data, bytes)
            or len(data) != COMMITMENT_BYTES
            or data[0] != VERSION
        ):
            raise ValueError('invalid commitment encoding')
        
        leaf_count = int.from_bytes(
            data[VERSION_BYTES:INTEGER_END],
            'big',
        )
        root = data[INTEGER_END:]
        return cls(leaf_count=leaf_count, root=root)


@dataclass(frozen=True)
class MerkleProof:
    """证明一个位置的消息：带上随机值和从叶子到根的兄弟摘要。"""
    index: int
    nonce: bytes
    siblings: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        validate_u64(self.index)
        _validate_fixed_bytes(self.nonce, NONCE_BYTES, 'opening randomness')

        if (type(self.siblings) is not tuple or len(self.siblings) > MAX_PROOF_DEPTH):
            raise ValueError('siblings must be a tuple of at most 64 digests')
        
        for sibling in self.siblings:
            _validate_fixed_bytes(sibling, HASH_BYTES, 'digest')

    def to_bytes(self) -> bytes:
        """依次写入版本、索引、随机值、路径长度和兄弟摘要。"""
        return (
            bytes([VERSION])
            + encode_u64(self.index)
            + self.nonce
            + len(self.siblings).to_bytes(DEPTH_BYTES, 'big')
            + b''.join(self.siblings)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> MerkleProof:
        """按路径长度读取兄弟摘要，多出或缺少字节都报 ValueError。"""
        if (
            not isinstance(data, bytes)
            or len(data) < PROOF_HEADER_BYTES
            or data[0] != VERSION
        ):
            raise ValueError('invalid proof encoding')
        
        depth = int.from_bytes(data[PROOF_NONCE_END:PROOF_HEADER_BYTES], 'big')

        expected_length = PROOF_HEADER_BYTES + HASH_BYTES * depth
        if depth > MAX_PROOF_DEPTH or len(data) != expected_length:
            raise ValueError('invalid proof length')
        
        index = int.from_bytes(data[VERSION_BYTES:INTEGER_END], 'big')

        nonce = data[INTEGER_END:PROOF_NONCE_END]

        siblings = tuple(
            data[offset:offset + HASH_BYTES]
            for offset in range(
                PROOF_HEADER_BYTES,
                len(data),
                HASH_BYTES,
            )
        )
        
        return cls(index=index, nonce=nonce, siblings=siblings)


# TODO(B-MULTIPROOF): 主逻辑完成后再启用下列协议草案。
# MULTIPROOF_SIBLING_COUNT_BYTES = 4
# @dataclass(frozen=True)
# class MultiProof:
#     indices: Tuple[int, ...]      # 非空、严格递增、无重复
#     nonces: Tuple[bytes, ...]     # 与 indices 一一对应
#     siblings: Tuple[bytes, ...]   # 从下到上，同层位置递增
#
# v1 encoding:
# version(1) || k(8) || indices(8*k) || nonces(32*k)
# || sibling_count(4) || siblings(32*s)
# total = 13 + 40*k + 32*s bytes


@dataclass(frozen=True)
class FullOpening:
    """全部消息及各自的随机值，用于重建整棵树。"""
    messages: Tuple[bytes, ...]
    nonces: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.messages) is not tuple or type(self.nonces) is not tuple:
            raise ValueError('full opening requires immutable tuples')
        validate_leaf_count(len(self.messages))

        if len(self.messages) != len(self.nonces):
            raise ValueError('message/nonce counts differ')
        
        for value in self.messages:
            if not isinstance(value, bytes):
                raise TypeError('encoded messages must be bytes')
            
        for nonce in self.nonces:
            _validate_fixed_bytes(nonce, NONCE_BYTES, 'opening randomness')

    def to_bytes(self) -> bytes:
        """写入版本和数量，再逐项写入消息长度、消息和随机值。"""
        return (
            bytes([VERSION])
            + encode_u64(len(self.messages))
            + b''.join(
                encode_u64(len(message)) + message + nonce
                for message, nonce in zip(self.messages, self.nonces)
            )
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> FullOpening:
        """用每项的长度找到消息末尾，紧接着读取 32 字节随机值。"""
        if (
            not isinstance(data, bytes)
            or len(data) < FULL_HEADER_BYTES
            or data[0] != VERSION
        ):
            raise ValueError('invalid full opening encoding')

        leaf_count = int.from_bytes(
            data[VERSION_BYTES:INTEGER_END],
            'big',
        )
        if leaf_count == 0:
            raise ValueError('invalid full opening count')

        messages = []
        nonces = []
        offset = FULL_HEADER_BYTES
        for _ in range(leaf_count):
            if offset + U64_BYTES > len(data):
                raise ValueError('truncated message length')

            message_length = int.from_bytes(
                data[offset:offset + U64_BYTES],
                'big',
            )
            offset += U64_BYTES
            message_end = offset + message_length
            nonce_end = message_end + NONCE_BYTES
            if nonce_end > len(data):
                raise ValueError('truncated message or nonce')
            messages.append(data[offset:message_end])
            nonces.append(data[message_end:nonce_end])
            offset = nonce_end

        if offset != len(data):
            raise ValueError('trailing full opening bytes')
        return cls(messages=tuple(messages), nonces=tuple(nonces))
