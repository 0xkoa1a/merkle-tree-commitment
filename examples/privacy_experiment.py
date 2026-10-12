"""低熵消息/随机值猜测演示。实验不充当 hiding 证明。"""
import itertools
import json

from merkle_commitment.sha3 import sha3_256
from merkle_commitment import tree as m


def run():
    # 复现旧方案：公开固定盐，正确候选算法能找回实际序列。
    salt, secret = b'merkle-tree-salt', '690'
    def old_root(values):
        row = [sha3_256(salt + x.encode()) for x in values]
        while len(row) > 1:
            row = [sha3_256(row[i] + row[i + 1]) if i + 1 < len(row) else row[i]
                   for i in range(0, len(row), 2)]
        return row[0]
    target = old_root(secret)
    tried, recovered = 0, None
    for candidate in itertools.permutations('0123456789', 3):
        tried += 1
        if old_root(candidate) == target:
            recovered = ''.join(candidate)
            break
    if recovered != secret:
        raise RuntimeError('failed to reproduce public-salt attack')

    # 弱随机值模拟：有效熵只有 4 bit，即使字段宽度为 32 字节也能猜出。
    weak = (11).to_bytes(32, 'big')
    weak_target = m._leaf_hash(2, 1, b'9', weak)
    weak_attempts, weak_found = 0, None
    for digit in '0123456789':
        for guess in range(16):
            weak_attempts += 1
            if m._leaf_hash(2, 1, digit.encode(), guess.to_bytes(32, 'big')) == weak_target:
                weak_found = {'message': digit, 'nonce': guess}
                break
        if weak_found is not None:
            break
    if weak_found != {'message': '9', 'nonce': 11}:
        raise RuntimeError('failed to reproduce weak-nonce attack')

    # 真实方案：开封索引0后，攻击者获得 r0 和索引1的摘要，没有 r1。
    public, state = m.commit([b'6', b'9'])
    message, proof = state.open(0)
    if not m.verify(public, 0, message, proof):
        raise RuntimeError('valid opening rejected')
    hidden_digest = proof.siblings[0]
    reuse_matches = [digit for digit in '0123456789'
                     if m._leaf_hash(2, 1, digit.encode(), proof.nonce) == hidden_digest]
    guessed_matches = []
    for digit in '0123456789':
        for guess in range(16):
            if m._leaf_hash(2, 1, digit.encode(), guess.to_bytes(32, 'big')) == hidden_digest:
                guessed_matches.append({'message': digit, 'nonce': guess})
    return {
        'legacy_public_salt': {'candidate_count': 720, 'attempts': tried, 'recovered': recovered},
        'weak_4bit_nonce': {'candidate_count': 160, 'attempts': weak_attempts, 'recovered': weak_found},
        'fresh_256bit_nonce_after_one_opening': {
            'reuse_opened_nonce_candidates': 10, 'reuse_matches': reuse_matches,
            'small_nonce_dictionary_candidates': 160, 'dictionary_matches': guessed_matches,
            'interpretation': '有限猜测实验；256-bit 随机值的隐藏性由文档中的随机预言机论证支持。'
        }
    }


if __name__ == '__main__':
    print(json.dumps(run(), ensure_ascii=False, indent=2))
