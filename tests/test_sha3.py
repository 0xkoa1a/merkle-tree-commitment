"""SHA3-256 的官方固定答案。"""

import json
from pathlib import Path
import unittest

from merkle_commitment.sha3 import sha3_256


class HashTests(unittest.TestCase):
    def test_nist_known_answers(self):
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
