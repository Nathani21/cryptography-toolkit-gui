import hashlib
from pathlib import Path

ALGORITHMS = ("sha256", "sha512")
CHUNK_SIZE = 64 * 1024


def _check_algorithm(algorithm: str) -> None:
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def hash_text(text: str, algorithm: str = "sha256") -> str:
    if not text:
        raise ValueError("Please enter some text first.")
    _check_algorithm(algorithm)
    return hashlib.new(algorithm, text.encode("utf-8")).hexdigest()


def hash_file(file_path, algorithm: str = "sha256") -> str:
    _check_algorithm(algorithm)
    h = hashlib.new(algorithm)
    with open(Path(file_path), "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def files_match(path1, path2, algorithm: str = "sha256") -> bool:
    return hash_file(path1, algorithm) == hash_file(path2, algorithm)


def file_matches_hash(file_path, expected_hash: str, algorithm: str = "sha256") -> bool:
    expected = "".join(expected_hash.split()).lower()
    if not expected:
        raise ValueError("Please paste the expected hash first.")
    return hash_file(file_path, algorithm) == expected