"""演示有效开封、篡改拒绝及完整开封。"""

from merkle_commitment import commit, verify, verify_all


def main():
    commitment, tree = commit(['6', '9', '0'])
    message, proof = tree.open(2)
    print('commitment:', commitment.to_bytes().hex())
    print('proof bytes:', len(proof.to_bytes()))
    print(
        'valid:',
        verify(commitment.to_bytes(), 2, message, proof.to_bytes()),
    )
    print('tampered:', verify(commitment, 2, b'changed', proof))
    print('full opening:', verify_all(commitment, tree.open_all()))


if __name__ == '__main__':
    main()
