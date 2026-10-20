import base64
import hashlib

import pytest

from merkle_proof import (
    DefaultHasher,
    RootMismatchError,
    compute_leaf_hash,
    decomp_incl_proof,
    inner_proof_size,
    root_from_inclusion_proof,
    verify_consistency,
    verify_inclusion,
    verify_match,
)


def test_hasher_hash_leaf_and_children():
    leaf = b"leaf-data"
    left = b"left"
    right = b"right"

    assert DefaultHasher.hash_leaf(leaf) == hashlib.sha256(b"\x00" + leaf).digest()
    assert (
        DefaultHasher.hash_children(left, right) == hashlib.sha256(b"\x01" + left + right).digest()
    )
    assert DefaultHasher.empty_root() == hashlib.sha256(b"").digest()
    assert DefaultHasher.size() == 32


def test_compute_leaf_hash_matches_rfc6962():
    payload = b"hello rekor"
    encoded = base64.b64encode(payload).decode("utf-8")

    expected = hashlib.sha256(b"\x00" + payload).hexdigest()
    assert compute_leaf_hash(encoded) == expected


def test_verify_inclusion_for_two_leaf_tree():
    leaf0 = DefaultHasher.hash_leaf(b"first")
    leaf1 = DefaultHasher.hash_leaf(b"second")
    root = DefaultHasher.hash_children(leaf0, leaf1)

    verify_inclusion(
        DefaultHasher,
        0,
        2,
        leaf0.hex(),
        [leaf1.hex()],
        root.hex(),
    )
    verify_inclusion(
        DefaultHasher,
        1,
        2,
        leaf1.hex(),
        [leaf0.hex()],
        root.hex(),
    )


def test_verify_inclusion_rejects_wrong_root(capsys):
    leaf0 = DefaultHasher.hash_leaf(b"first")
    leaf1 = DefaultHasher.hash_leaf(b"second")
    root = DefaultHasher.hash_children(leaf0, leaf1)

    with pytest.raises(RootMismatchError):
        verify_inclusion(DefaultHasher, 0, 2, leaf0.hex(), [leaf1.hex()], root.hex() + "00")

    verify_inclusion(DefaultHasher, 0, 2, leaf0.hex(), [leaf1.hex()], root.hex(), debug=True)
    output = capsys.readouterr().out
    assert "Calculated root hash" in output
    assert "Given root hash" in output


def test_verify_inclusion_debug_prints_roots(capsys):
    leaf = DefaultHasher.hash_leaf(b"only")
    verify_inclusion(DefaultHasher, 0, 1, leaf.hex(), [], leaf.hex(), debug=True)
    output = capsys.readouterr().out
    assert leaf.hex() in output


def test_root_from_inclusion_proof_validates_arguments():
    leaf = DefaultHasher.hash_leaf(b"only")

    with pytest.raises(ValueError, match="index is beyond size"):
        root_from_inclusion_proof(DefaultHasher, 1, 1, leaf, [])

    with pytest.raises(ValueError, match="unexpected size"):
        root_from_inclusion_proof(DefaultHasher, 0, 1, b"short", [])

    with pytest.raises(ValueError, match="wrong proof size"):
        root_from_inclusion_proof(DefaultHasher, 0, 2, leaf, [])


def test_verify_match_reports_both_roots():
    with pytest.raises(RootMismatchError) as excinfo:
        verify_match(b"\x01" * 32, b"\x02" * 32)

    message = str(excinfo.value)
    assert "calculated root" in message
    assert "does not match expected root" in message


def test_proof_size_helpers():
    assert inner_proof_size(0, 1) == 0
    assert inner_proof_size(0, 2) == 1
    assert decomp_incl_proof(3, 8) == (3, 0)


def test_verify_consistency_for_growing_tree():
    leaf0 = DefaultHasher.hash_leaf(b"first")
    leaf1 = DefaultHasher.hash_leaf(b"second")
    leaf2 = DefaultHasher.hash_leaf(b"third")

    root1 = DefaultHasher.hash_children(leaf0, leaf1)
    root2 = DefaultHasher.hash_children(root1, leaf2)

    verify_consistency(
        DefaultHasher,
        2,
        3,
        [leaf2.hex()],
        root1.hex(),
        root2.hex(),
    )


def test_verify_consistency_equal_sizes():
    root = DefaultHasher.hash_leaf(b"only").hex()

    verify_consistency(DefaultHasher, 2, 2, [], root, root)

    with pytest.raises(RootMismatchError):
        verify_consistency(DefaultHasher, 2, 2, [], root, root[:-2] + "00")

    with pytest.raises(ValueError, match="bytearray_proof is not empty"):
        verify_consistency(DefaultHasher, 2, 2, [root], root, root)


def test_verify_consistency_zero_and_invalid_sizes():
    root = DefaultHasher.hash_leaf(b"only").hex()

    verify_consistency(DefaultHasher, 0, 3, [], root, root)

    with pytest.raises(ValueError, match="expected empty bytearray_proof"):
        verify_consistency(DefaultHasher, 0, 3, [root], root, root)

    with pytest.raises(ValueError, match="size2 .* < size1"):
        verify_consistency(DefaultHasher, 3, 2, [], root, root)


def test_verify_consistency_rejects_empty_or_wrong_sized_proof():
    leaf0 = DefaultHasher.hash_leaf(b"first")
    leaf1 = DefaultHasher.hash_leaf(b"second")
    root1 = leaf0
    root2 = DefaultHasher.hash_children(leaf0, leaf1)

    with pytest.raises(ValueError, match="empty bytearray_proof"):
        verify_consistency(DefaultHasher, 1, 2, [], root1.hex(), root2.hex())

    with pytest.raises(ValueError, match="wrong bytearray_proof size"):
        verify_consistency(
            DefaultHasher,
            1,
            2,
            [leaf0.hex(), leaf1.hex()],
            root1.hex(),
            root2.hex(),
        )
