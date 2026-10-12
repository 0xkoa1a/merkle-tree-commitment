"""v1 固定编码、往返解析和字节输入验证。"""

import json
from pathlib import Path
import unittest

from merkle_commitment import (
    Commitment,
    FullOpening,
    MerkleProof,
    commit,
    verify,
    verify_all,
)


class EncodingTests(unittest.TestCase):
    def test_v1_golden_encodings_and_byte_inputs(self):
        data_path = Path(__file__).with_name('data') / 'v1_encoding.json'
        golden = json.loads(data_path.read_text())
        objects = {
            'commitment': Commitment(leaf_count=3, root=bytes(range(32))),
            'proof': MerkleProof(
                index=1,
                nonce=bytes(range(32)),
                siblings=(b'A' * 32, b'B' * 32),
            ),
            'full_opening': FullOpening(
                messages=(b'a', b''),
                nonces=(b'\x11' * 32, b'\x22' * 32),
            ),
        }

        for name, value in objects.items():
            with self.subTest(object=name):
                encoded = bytes.fromhex(golden[name])
                self.assertEqual(value.to_bytes(), encoded)
                self.assertEqual(type(value).from_bytes(encoded), value)
                self.assertEqual(type(value).from_bytes(value.to_bytes()), value)

        commitment, tree = commit([b'a', b'b', b'c'])
        message, proof = tree.open(1)
        full_opening = tree.open_all()
        self.assertTrue(
            verify(commitment.to_bytes(), 1, message, proof.to_bytes())
        )
        self.assertTrue(
            verify_all(commitment.to_bytes(), full_opening.to_bytes())
        )


if __name__ == '__main__':
    unittest.main()
