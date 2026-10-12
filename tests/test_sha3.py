"""SHA3 的官方固定答案与输入语义。"""
import json
from pathlib import Path
import unittest

from merkle_commitment.sha3 import sha3_256, sha3_256_digest


class HashTests(unittest.TestCase):
    def test_nist_known_answers(self):
        data = json.loads((Path(__file__).with_name('data') / 'sha3_vectors.json').read_text())
        self.assertEqual(len(data['vectors']), 140)
        self.assertEqual({item['length_bytes'] for item in data['vectors']},
                         set(range(137)) | {273, 410, 4109})
        self.assertEqual(len({item['id'] for item in data['vectors']}), 140)
        self.assertEqual(data['source']['organization'], 'NIST CAVP')
        for item in data['vectors']:
            with self.subTest(vector=item['id']):
                message = bytes.fromhex(item['message_hex'])
                self.assertEqual(len(message), item['length_bytes'])
                self.assertEqual(len(message) * 8, item['length_bits'])
                self.assertEqual(sha3_256(message), item['digest_hex'])

    def test_abc_known_answer(self):
        self.assertEqual(sha3_256(b'abc'),
                         '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532')

    def test_unicode_encoding_and_digest_size(self):
        self.assertEqual(sha3_256('你好'), sha3_256('你好'.encode('utf-8')))
        self.assertEqual(len(sha3_256_digest(b'abc')), 32)
        for value in (None, 1, [], bytearray(b'x')):
            with self.assertRaises(TypeError):
                sha3_256(value)


