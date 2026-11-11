import hashlib

import pytest

from hashing import file_matches_hash, files_match, hash_file, hash_text

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_text_known_value():
    assert hash_text("abc") == ABC_SHA256


def test_hash_text_sha512_length():
    assert len(hash_text("abc", "sha512")) == 127


def test_hash_text_empty_raises():
    with pytest.raises(ValueError):
        hash_text("")


def test_hash_text_unsupported_algorithm():
    with pytest.raises(ValueError):
        hash_text("abc", "md4")


def test_hash_file_matches_text_hash(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    assert hash_file(f) == ABC_SHA256


def test_hash_file_larger_than_one_chunk(tmp_path):
    data = b"x" * 200_000
    f = tmp_path / "big.bin"
    f.write_bytes(data)
    assert hash_file(f) == hashlib.sha256(data).hexdigest()


def test_hash_file_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "nope.txt")


def test_files_match_identical_copy(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"same content")
    b.write_bytes(b"same content")
    assert files_match(a, b) is True


def test_files_match_detects_tampering(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"same content")
    b.write_bytes(b"same contenT")
    assert files_match(a, b) is False


def test_file_matches_hash_ignores_case_and_spaces(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    pasted = "  " + ABC_SHA256.upper() + "\n"
    assert file_matches_hash(f, pasted) is True


def test_file_matches_hash_wrong_hash(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abd")
    assert file_matches_hash(f, ABC_SHA256) is False


def test_file_matches_hash_empty_expected_raises(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    with pytest.raises(ValueError):
        file_matches_hash(f, "   ")