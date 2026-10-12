"""演示有效开封、篡改拒绝及完整开封。"""

from merkle_commitment import commit, verify, verify_all


def main():
    public, state = commit(['a', 'b', 'a', '你好'])
    message, proof = state.open(2)
    print('commitment:', public.to_bytes().hex())
    print('proof bytes:', len(proof.to_bytes()))
    print('valid:', verify(public.to_bytes(), 2, message, proof.to_bytes()))
    print('tampered:', verify(public, 2, b'changed', proof))
    print('full opening:', verify_all(public, state.open_all()))


if __name__ == '__main__':
    main()
