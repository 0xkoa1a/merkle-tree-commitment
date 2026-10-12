"""实现正确性基线：NIST 固定答案、独立树规格、代表性篡改与字节往返。"""

import json
from pathlib import Path
from dataclasses import replace
import unittest

from merkle_commitment import tree as mt
from merkle_commitment.sha3 import sha3_256, sha3_256_digest


def _reference_root(messages, nonces):
    """独立编码、递归计算承诺，只共享经 NIST 校验的哈希原语。

    不调用生产树或协议 helper，避免建树与验证共同出错却彼此吻合。
    """
    n = len(messages)

    def u64(value):
        """直接按规格写出 8 字节大端整数。"""
        return value.to_bytes(8, 'big')

    def subtree(start, width):
        """单位置区间区分真实/占位叶，否则递归合并两个半区间。"""
        if width == 1:
            if start >= n:
                return sha3_256_digest(b'\x02' + u64(n) + u64(start))
            message = messages[start]
            return sha3_256_digest(
                b'\x00' + u64(n) + u64(start) + u64(len(message))
                + message + nonces[start]
            )
        half = width // 2
        return sha3_256_digest(
            b'\x01' + subtree(start, half) + subtree(start + half, half)
        )

    capacity = 1 << (n - 1).bit_length()
    return sha3_256_digest(b'\x03' + u64(n) + subtree(0, capacity))


def _flip(data):
    """改一位但保持长度，进入哈希比较而非字段长度拒绝分支。"""
    return bytes([data[0] ^ 1]) + data[1:]


class CommitmentTests(unittest.TestCase):
    def test_core_commit_open_verify_against_reference(self):
        """四种树形检查独立根、首/中/末位置和完整开封。

        单叶、占位、完整二叉树及刚跨二次幂约束主要结构分支；
        大规模与随机分布属于 experiments，不靠这里的样例证明安全性。
        """
        for n in (1, 3, 8, 9):
            with self.subTest(n=n):
                messages = ([b'a', b'', '你好'] * 3)[:n]
                commitment, tree = mt.commit(messages)
                opening = tree.open_all()
                self.assertEqual(
                    commitment.digest,
                    _reference_root(opening.messages, opening.nonces),
                )
                for index in sorted({0, n // 2, n - 1}):
                    message, proof = tree.open(index)
                    self.assertEqual(message, opening.messages[index])
                    self.assertTrue(mt.verify(commitment, index, message, proof))
                    depth = (n - 1).bit_length()
                    self.assertEqual(len(proof.siblings), depth)
                    self.assertEqual(len(proof.to_bytes()), 43 + 32 * depth)
                self.assertTrue(mt.verify_all(commitment, opening))

    def test_representative_tampering_is_rejected(self):
        """改变消息、nonce、兄弟、公开根及完整开封内容，均须拒绝。

        各变体仍是合法协议对象，只保留语义不同的篡改，不展开类型矩阵。
        """
        commitment, tree = mt.commit([b'a', b'b', b'c'])
        message, proof = tree.open(1)
        variants = (
            (commitment, b'changed', proof),
            (commitment, message, replace(proof, nonce=_flip(proof.nonce))),
            (commitment, message, replace(
                proof, siblings=(_flip(proof.siblings[0]),) + proof.siblings[1:],
            )),
            (replace(commitment, digest=_flip(commitment.digest)), message, proof),
        )
        for case, (candidate, value, evidence) in enumerate(variants):
            with self.subTest(case=case):
                self.assertFalse(mt.verify(candidate, 1, value, evidence))
        opening = tree.open_all()
        changed = replace(opening, messages=(b'changed',) + opening.messages[1:])
        self.assertFalse(mt.verify_all(commitment, changed))

    def test_wire_round_trip(self):
        """三类对象各往返一次，再通过公开的字节验证入口完成开封。

        保留格式连接处的基线检查，不另设外部 ABI 固定答案和拒绝矩阵。
        """
        commitment, tree = mt.commit([b'a', b'', '你好'])
        message, proof = tree.open(2)
        opening = tree.open_all()
        for value in (commitment, proof, opening):
            with self.subTest(object=type(value).__name__):
                self.assertEqual(type(value).from_bytes(value.to_bytes()), value)
        self.assertTrue(mt.verify(commitment.to_bytes(), 2, message, proof.to_bytes()))
        self.assertTrue(mt.verify_all(commitment.to_bytes(), opening.to_bytes()))

    def test_batch_openings_and_proof_consumption(self):
        """共享路径覆盖单叶、占位、相邻/跨子树及全开，并严格消费证明。

        根先与独立递归规格比较；批量消息再与单项开封对照。
        少量拒绝案例检查新入口的消息绑定、期望位置和边界摘要数量。
        """
        for n in (1, 3, 8, 9):
            commitment, tree = mt.commit([str(i) for i in range(n)])
            full = tree.open_all()
            self.assertEqual(commitment.digest, _reference_root(full.messages, full.nonces))
            subsets = {(0,), tuple(range(min(2, n))), tuple(sorted({0, n // 2, n - 1})),
                       tuple(range(n))}
            for indices in sorted(subsets):
                with self.subTest(n=n, indices=indices):
                    messages, proof = tree.open_many(iter(indices))
                    self.assertEqual(messages, tuple(tree.open(i)[0] for i in indices))
                    self.assertTrue(mt.verify_many(commitment, indices, messages, proof))
                    self.assertEqual(len(proof.to_bytes()), 13 + 40 * len(indices) + 32 * len(proof.siblings))
                    self.assertEqual(mt.BatchProof.from_bytes(proof.to_bytes()), proof)
                    self.assertTrue(mt.verify_many(
                        commitment.to_bytes(), indices, messages, proof.to_bytes(),
                    ))
        commitment, tree = mt.commit([str(i) for i in range(9)])
        indices = (0, 3, 8)
        messages, proof = tree.open_many(indices)
        self.assertFalse(mt.verify_many(commitment, indices, (b'changed',) + messages[1:], proof))
        self.assertFalse(mt.verify_many(commitment, (1, 3, 8), messages, proof))
        for siblings in (proof.siblings[:-1], proof.siblings + (bytes(32),)):
            self.assertFalse(mt.verify_many(
                commitment, indices, messages, replace(proof, siblings=siblings),
            ))
        for invalid in ((3, 0, 8), (0, 0, 8)):
            with self.assertRaises(ValueError):
                replace(proof, indices=invalid)
        for encoded in (proof.to_bytes()[:-1], proof.to_bytes() + b'x'):
            self.assertFalse(mt.verify_many(commitment, indices, messages, encoded))



class HashTests(unittest.TestCase):
    def test_nist_known_answers(self):
        """用 140 条 NIST CAVP 向量校验手写 SHA3-256。

        先检查向量来源、编号唯一性和长度集合，避免测试数据被误删后仍然
        显示通过；再逐条比较摘要。0--136 B 的连续输入覆盖填充边界，三条
        长消息覆盖多块吸收，最后的 ``abc`` 作为无需查数据文件的直观样例。
        """
        data_path = Path(__file__).with_name('data') / 'sha3_vectors.json'
        data = json.loads(data_path.read_text())
        vectors = data['vectors']

        self.assertEqual(len(vectors), 140)
        self.assertEqual(
            {item['length_bytes'] for item in vectors},
            set(range(137)) | {273, 410, 4109},
        )
        self.assertEqual(len({item['id'] for item in vectors}), 140)
        self.assertEqual(data['source']['organization'], 'NIST CAVP')

        for item in vectors:
            with self.subTest(vector=item['id']):
                message = bytes.fromhex(item['message_hex'])
                self.assertEqual(len(message), item['length_bytes'])
                self.assertEqual(len(message) * 8, item['length_bits'])
                self.assertEqual(sha3_256(message), item['digest_hex'])

        self.assertEqual(
            sha3_256(b'abc'),
            '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
        )



if __name__ == '__main__':
    unittest.main()

