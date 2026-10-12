"""承诺协议的正确性、独立规格和拒绝路径。"""

from dataclasses import replace
import unittest

from merkle_commitment import tree as tree_module
from merkle_commitment.sha3 import sha3_256_digest


def _flip_first_byte(data: bytes) -> bytes:
    return bytes([data[0] ^ 1]) + data[1:]


def _reference_root(messages, nonces):
    """按协议字节格式递归计算根，不复用生产代码的树辅助函数。"""
    leaf_count = len(messages)
    capacity = 1 << (leaf_count - 1).bit_length()

    def encode_u64_for_test(value):
        return value.to_bytes(8, 'big')

    def subtree(start, width):
        if width == 1:
            if start >= leaf_count:
                return sha3_256_digest(
                    b'\x02'
                    + encode_u64_for_test(leaf_count)
                    + encode_u64_for_test(start)
                )
            message = messages[start]
            return sha3_256_digest(
                b'\x00'
                + encode_u64_for_test(leaf_count)
                + encode_u64_for_test(start)
                + encode_u64_for_test(len(message))
                + message
                + nonces[start]
            )

        half = width // 2
        return sha3_256_digest(
            b'\x01' + subtree(start, half) + subtree(start + half, half)
        )

    return sha3_256_digest(
        b'\x03'
        + encode_u64_for_test(leaf_count)
        + subtree(0, capacity)
    )


class CommitmentTests(unittest.TestCase):
    def setUp(self):
        messages = [b'a', b'b', b'a', b'', '你好']
        self.commitment, self.tree = tree_module.commit(messages)
        self.message, self.proof = self.tree.open(2)

    def test_honest_openings_for_tree_sizes(self):
        for leaf_count in (1, 2, 3, 5, 7, 8, 9, 16, 17, 32):
            with self.subTest(leaf_count=leaf_count):
                messages = [bytes([index % 3]) for index in range(leaf_count)]
                commitment, tree = tree_module.commit(messages)

                for index in range(leaf_count):
                    message, proof = tree.open(index)
                    self.assertTrue(
                        tree_module.verify(commitment, index, message, proof)
                    )
                    self.assertEqual(
                        len(proof.siblings),
                        (leaf_count - 1).bit_length(),
                    )
                    self.assertEqual(
                        len(proof.to_bytes()),
                        43 + 32 * len(proof.siblings),
                    )

                self.assertTrue(
                    tree_module.verify_all(commitment, tree.open_all())
                )

    def test_commitment_matches_recursive_specification(self):
        for leaf_count in (1, 2, 3, 5, 8, 9):
            with self.subTest(leaf_count=leaf_count):
                messages = tuple(
                    bytes([index % 4]) for index in range(leaf_count)
                )
                commitment, tree = tree_module.commit(messages)
                opening = tree.open_all()
                self.assertEqual(
                    commitment.root,
                    _reference_root(opening.messages, opening.nonces),
                )

    def test_single_opening_tampering_rejected(self):
        for message in (b'changed', self.message + b'\x00'):
            with self.subTest(field='message', value=message):
                self.assertFalse(
                    tree_module.verify(
                        self.commitment, 2, message, self.proof
                    )
                )

        tampered_nonce = replace(
            self.proof,
            nonce=_flip_first_byte(self.proof.nonce),
        )
        self.assertFalse(
            tree_module.verify(
                self.commitment, 2, self.message, tampered_nonce
            )
        )

        for level_index in range(len(self.proof.siblings)):
            siblings = list(self.proof.siblings)
            siblings[level_index] = _flip_first_byte(siblings[level_index])
            tampered_proof = replace(
                self.proof,
                siblings=tuple(siblings),
            )
            with self.subTest(field='sibling', level=level_index):
                self.assertFalse(
                    tree_module.verify(
                        self.commitment,
                        2,
                        self.message,
                        tampered_proof,
                    )
                )

        tampered_root = replace(
            self.commitment,
            root=_flip_first_byte(self.commitment.root),
        )
        self.assertFalse(
            tree_module.verify(
                tampered_root, 2, self.message, self.proof
            )
        )

        for leaf_count in (1, 4, 6, 8):
            with self.subTest(field='leaf_count', value=leaf_count):
                tampered_commitment = replace(
                    self.commitment,
                    leaf_count=leaf_count,
                )
                self.assertFalse(
                    tree_module.verify(
                        tampered_commitment,
                        2,
                        self.message,
                        self.proof,
                    )
                )

        path_variants = (
            self.proof.siblings[:-1],
            self.proof.siblings + (b'\x00' * 32,),
            self.proof.siblings[::-1],
        )
        for siblings in path_variants:
            with self.subTest(field='path', length=len(siblings)):
                self.assertFalse(
                    tree_module.verify(
                        self.commitment,
                        2,
                        self.message,
                        replace(self.proof, siblings=siblings),
                    )
                )

        for other_index in (0, 1, 3, 4):
            relabeled_proof = replace(self.proof, index=other_index)
            with self.subTest(field='index', value=other_index):
                self.assertFalse(
                    tree_module.verify(
                        self.commitment,
                        other_index,
                        self.message,
                        relabeled_proof,
                    )
                )

    def test_full_opening_tampering_rejected(self):
        opening = self.tree.open_all()
        variants = (
            replace(
                opening,
                messages=(b'changed',) + opening.messages[1:],
            ),
            tree_module.FullOpening(
                messages=opening.messages[::-1],
                nonces=opening.nonces[::-1],
            ),
            tree_module.FullOpening(
                messages=opening.messages[:-1],
                nonces=opening.nonces[:-1],
            ),
            replace(
                opening,
                nonces=(b'\x00' * 32,) + opening.nonces[1:],
            ),
        )
        for variant in variants:
            with self.subTest(opening=variant):
                self.assertFalse(
                    tree_module.verify_all(self.commitment, variant)
                )

    def test_invalid_indices_rejected(self):
        invalid_indices = (-1, 2**64, True, 2.0, '2', None)
        for index in invalid_indices:
            with self.subTest(index=index):
                self.assertFalse(
                    tree_module.verify(
                        self.commitment, index, self.message, self.proof
                    )
                )
                with self.assertRaises((ValueError, TypeError)):
                    self.tree.prove(index)

        for index in (5, 7):
            with self.subTest(out_of_range=index):
                proof = replace(self.proof, index=index)
                self.assertFalse(
                    tree_module.verify(
                        self.commitment, index, self.message, proof
                    )
                )
                with self.assertRaises(ValueError):
                    self.tree.prove(index)

    def test_api_inputs_rejected(self):
        for messages in ([], [None], [42], 'abc', b'abc'):
            with self.subTest(messages=messages):
                with self.assertRaises((ValueError, TypeError)):
                    tree_module.commit(messages)

        invalid_proof_fields = (
            {'index': True},
            {'nonce': b'bad'},
            {'siblings': (b'bad',)},
            {'siblings': []},
            {'siblings': (b'\x00' * 32,) * 65},
        )
        for fields in invalid_proof_fields:
            with self.subTest(fields=fields):
                with self.assertRaises(ValueError):
                    replace(self.proof, **fields)

        with self.assertRaises(ValueError):
            tree_module.Commitment(
                leaf_count=True,
                root=self.commitment.root,
            )
        with self.assertRaises(ValueError):
            tree_module.Commitment(leaf_count=1, root=b'bad')
        self.assertFalse(
            tree_module.verify({}, 2, self.message, {})
        )
        self.assertFalse(tree_module.verify_all(self.commitment, {}))

    def test_fresh_independent_nonces(self):
        other_commitment, other_tree = tree_module.commit(
            [b'a', b'b', b'a', b'', '你好']
        )
        self.assertNotEqual(other_commitment.root, self.commitment.root)

        nonces = self.tree.open_all().nonces
        other_nonces = other_tree.open_all().nonces
        self.assertEqual(len(set(nonces)), len(nonces))
        self.assertNotEqual(other_nonces, nonces)
        # 这里只检查生成路径没有复用 nonce，不是随机性统计检验。

    def test_binary_parsers_reject_malformed_inputs(self):
        commitment_bytes = self.commitment.to_bytes()
        bad_commitments = (
            b'',
            commitment_bytes[:-1],
            commitment_bytes + b'x',
            b'\x02' + commitment_bytes[1:],
            b'\x01' + b'\x00' * 8 + commitment_bytes[9:],
            bytearray(commitment_bytes),
            None,
        )
        for data in bad_commitments:
            with self.subTest(object='commitment', data=data):
                with self.assertRaises(ValueError):
                    tree_module.Commitment.from_bytes(data)
                self.assertFalse(
                    tree_module.verify(data, 2, self.message, self.proof)
                )

        proof_bytes = self.proof.to_bytes()
        bad_proofs = (
            b'',
            proof_bytes[:-1],
            proof_bytes + b'x',
            b'\x02' + proof_bytes[1:],
            proof_bytes[:41] + b'\x00\x41' + proof_bytes[43:],
            bytearray(proof_bytes),
            None,
        )
        for data in bad_proofs:
            with self.subTest(object='proof', data=data):
                with self.assertRaises(ValueError):
                    tree_module.MerkleProof.from_bytes(data)
                self.assertFalse(
                    tree_module.verify(
                        self.commitment, 2, self.message, data
                    )
                )

        opening_bytes = self.tree.open_all().to_bytes()
        bad_openings = (
            b'',
            opening_bytes[:-1],
            opening_bytes + b'x',
            b'\x02' + opening_bytes[1:],
            b'\x01' + b'\xff' * 8 + opening_bytes[9:],
            opening_bytes[:9] + b'\xff' * 8 + opening_bytes[17:],
            bytearray(opening_bytes),
            None,
        )
        for data in bad_openings:
            with self.subTest(object='full_opening', data=data):
                with self.assertRaises(ValueError):
                    tree_module.FullOpening.from_bytes(data)
                self.assertFalse(
                    tree_module.verify_all(self.commitment, data)
                )


if __name__ == '__main__':
    unittest.main()
