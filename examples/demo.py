"""演示单项/批量/完整开封及篡改拒绝。"""

from merkle_commitment import commit, verify, verify_all, verify_many


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
    indices = (0, 2)
    messages, batch = tree.open_many(indices)
    print('batch proof bytes:', len(batch.to_bytes()))
    print('batch opening:', verify_many(
        commitment.to_bytes(), indices, messages, batch.to_bytes(),
    ))


if __name__ == '__main__':
    main()
