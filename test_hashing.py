import hashlib

import pytest

from hashing import detect_algorithm, file_matches_hash, files_match, hash_file, hash_text

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_text_known_value():
    assert hash_text("abc") == ABC_SHA256


@pytest.mark.parametrize(
    "algorithm, expected",
    [
        ("md5", "900150983cd24fb0d6963f7d28e17f72"),
        ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ],
)
def test_hash_text_legacy_algorithms(algorithm, expected):
    assert hash_text("abc", algorithm) == expected


@pytest.mark.parametrize(
    "algorithm, expected",
    [
        ("md5", "900150983cd24fb0d6963f7d28e17f72"),
        ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ],
)
def test_hash_file_legacy_algorithms(tmp_path, algorithm, expected):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    assert hash_file(f, algorithm) == expected


def test_file_matches_hash_with_md5(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes(b"abc")
    assert file_matches_hash(f, "900150983CD24FB0D6963F7D28E17F72", "md5") is True


def test_hash_text_sha512_length():
    assert len(hash_text("abc", "sha512")) == 128


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


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256", "sha512"])
def test_detect_algorithm_from_real_hashes(algorithm):
    assert detect_algorithm(hash_text("abc", algorithm)) == algorithm


def test_detect_algorithm_ignores_case_and_whitespace():
    assert detect_algorithm("  " + ABC_SHA256.upper() + "\n") == "sha256"


def test_detect_algorithm_unknown_length():
    assert detect_algorithm("abcdef") is None


def test_detect_algorithm_not_hex():
    assert detect_algorithm("z" * 64) is None


def test_detect_algorithm_empty():
    assert detect_algorithm("") is None
    assert detect_algorithm("   ") is None