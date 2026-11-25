import base64
import os

import pytest

from crypto import (
    FILE_CHUNK_SIZE,
    FILE_HEADER_SIZE,
    FILE_MAGIC,
    TAG_SIZE,
    decrypt_file,
    decrypt_text,
    encrypt_file,
    encrypt_text,
)


def test_round_trip():
    package = encrypt_text("Hello, AES!", "correct horse")
    assert decrypt_text(package, "correct horse") == "Hello, AES!"


def test_round_trip_unicode():
    message = "héllo ₦aira 😀"
    package = encrypt_text(message, "pässword")
    assert decrypt_text(package, "pässword") == message


def test_same_input_gives_different_output():
    a = encrypt_text("same message", "same password")
    b = encrypt_text("same message", "same password")
    assert a != b


def test_wrong_password_raises():
    package = encrypt_text("secret", "right")
    with pytest.raises(ValueError, match="Wrong password"):
        decrypt_text(package, "wrong")


def test_tampered_data_raises():
    package = encrypt_text("secret", "pw")
    raw = bytearray(base64.b64decode(package))
    raw[-1] ^= 1
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValueError, match="Wrong password"):
        decrypt_text(tampered, "pw")


def test_not_base64_raises():
    with pytest.raises(ValueError, match="encrypted text"):
        decrypt_text("this is not base64!!", "pw")


def test_too_short_raises():
    short = base64.b64encode(b"tiny").decode("ascii")
    with pytest.raises(ValueError, match="encrypted text"):
        decrypt_text(short, "pw")


def test_package_survives_whitespace():
    package = encrypt_text("secret", "pw")
    wrapped = package[:20] + "\n" + package[20:] + "  "
    assert decrypt_text(wrapped, "pw") == "secret"


def test_empty_inputs_raise():
    with pytest.raises(ValueError):
        encrypt_text("", "pw")
    with pytest.raises(ValueError):
        encrypt_text("text", "")
    with pytest.raises(ValueError):
        decrypt_text("   ", "pw")
    with pytest.raises(ValueError):
        decrypt_text("AAAA", "")

    


# ---------- File encryption ----------
def round_trip(tmp_path, data, password="pw"):
    plain = tmp_path / "plain.bin"
    sealed = tmp_path / "sealed.ctk"
    restored = tmp_path / "restored.bin"
    plain.write_bytes(data)
    encrypt_file(plain, sealed, password)
    decrypt_file(sealed, restored, password)
    return sealed, restored.read_bytes()


def test_file_round_trip_small(tmp_path):
    _, restored = round_trip(tmp_path, b"hello file")
    assert restored == b"hello file"


def test_file_round_trip_empty(tmp_path):
    sealed, restored = round_trip(tmp_path, b"")
    assert restored == b""
    assert sealed.stat().st_size == FILE_HEADER_SIZE + TAG_SIZE


@pytest.mark.parametrize(
    "size", [FILE_CHUNK_SIZE, 2 * FILE_CHUNK_SIZE, 2 * FILE_CHUNK_SIZE + 123]
)
def test_file_round_trip_across_chunk_boundaries(tmp_path, size):
    data = os.urandom(size)
    _, restored = round_trip(tmp_path, data)
    assert restored == data


def test_encrypted_file_has_header_and_is_not_plaintext(tmp_path):
    data = b"find me if you can" * 100
    sealed, _ = round_trip(tmp_path, data)
    content = sealed.read_bytes()
    assert content.startswith(FILE_MAGIC)
    assert b"find me if you can" not in content
    assert len(content) == FILE_HEADER_SIZE + len(data) + TAG_SIZE


def test_same_file_encrypts_differently_each_time(tmp_path):
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"same content")
    encrypt_file(plain, tmp_path / "a.ctk", "pw")
    encrypt_file(plain, tmp_path / "b.ctk", "pw")
    assert (tmp_path / "a.ctk").read_bytes() != (tmp_path / "b.ctk").read_bytes()


@pytest.fixture(scope="module")
def three_chunk_file(tmp_path_factory):
    folder = tmp_path_factory.mktemp("sealed")
    plain = folder / "plain.bin"
    plain.write_bytes(os.urandom(2 * FILE_CHUNK_SIZE + 500))
    sealed = folder / "sealed.ctk"
    encrypt_file(plain, sealed, "right")
    return sealed


def try_decrypt(tmp_path, sealed_bytes, password="right"):
    sealed = tmp_path / "input.ctk"
    sealed.write_bytes(sealed_bytes)
    target = tmp_path / "out.bin"
    with pytest.raises(ValueError) as error:
        decrypt_file(sealed, target, password)
    assert not target.exists()
    assert not (tmp_path / "out.bin.part").exists()
    return str(error.value)


def test_wrong_password_is_rejected(tmp_path, three_chunk_file):
    message = try_decrypt(tmp_path, three_chunk_file.read_bytes(), "wrong")
    assert "Wrong password" in message


def test_changed_byte_is_detected(tmp_path, three_chunk_file):
    data = bytearray(three_chunk_file.read_bytes())
    data[FILE_HEADER_SIZE + FILE_CHUNK_SIZE + 50] ^= 1
    assert "Wrong password" in try_decrypt(tmp_path, bytes(data))


def test_changed_header_is_detected(tmp_path, three_chunk_file):
    data = bytearray(three_chunk_file.read_bytes())
    data[FILE_HEADER_SIZE - 1] ^= 1
    assert "Wrong password" in try_decrypt(tmp_path, bytes(data))


def test_file_cut_off_at_a_chunk_boundary_is_detected(tmp_path, three_chunk_file):
    sealed_size = FILE_CHUNK_SIZE + TAG_SIZE
    data = three_chunk_file.read_bytes()[: FILE_HEADER_SIZE + 2 * sealed_size]
    assert "Wrong password" in try_decrypt(tmp_path, data)


def test_file_cut_off_mid_chunk_is_detected(tmp_path, three_chunk_file):
    data = three_chunk_file.read_bytes()[:-100]
    assert "Wrong password" in try_decrypt(tmp_path, data)


def test_swapped_chunks_are_detected(tmp_path, three_chunk_file):
    sealed_size = FILE_CHUNK_SIZE + TAG_SIZE
    data = three_chunk_file.read_bytes()
    header = data[:FILE_HEADER_SIZE]
    first = data[FILE_HEADER_SIZE : FILE_HEADER_SIZE + sealed_size]
    second = data[FILE_HEADER_SIZE + sealed_size : FILE_HEADER_SIZE + 2 * sealed_size]
    rest = data[FILE_HEADER_SIZE + 2 * sealed_size :]
    assert "Wrong password" in try_decrypt(tmp_path, header + second + first + rest)


def test_a_file_this_app_did_not_make_is_rejected(tmp_path):
    message = try_decrypt(tmp_path, os.urandom(200))
    assert "doesn't look like" in message


def test_a_too_short_file_is_rejected(tmp_path):
    assert "doesn't look like" in try_decrypt(tmp_path, b"CT")


def test_a_newer_file_version_is_reported(tmp_path, three_chunk_file):
    data = bytearray(three_chunk_file.read_bytes())
    data[4] = 2
    assert "newer version" in try_decrypt(tmp_path, bytes(data))


def test_failed_decrypt_leaves_an_existing_file_alone(tmp_path, three_chunk_file):
    target = tmp_path / "precious.txt"
    target.write_bytes(b"precious")
    with pytest.raises(ValueError):
        decrypt_file(three_chunk_file, target, "wrong")
    assert target.read_bytes() == b"precious"


def test_successful_encrypt_replaces_an_existing_file(tmp_path):
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"data")
    target = tmp_path / "out.ctk"
    target.write_bytes(b"old")
    encrypt_file(plain, target, "pw")
    assert target.read_bytes().startswith(FILE_MAGIC)


def test_file_functions_need_a_password(tmp_path):
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"data")
    with pytest.raises(ValueError, match="password"):
        encrypt_file(plain, tmp_path / "out.ctk", "")
    with pytest.raises(ValueError, match="password"):
        decrypt_file(plain, tmp_path / "out.bin", "")


def test_file_functions_refuse_to_overwrite_their_own_source(tmp_path):
    plain = tmp_path / "plain.bin"
    plain.write_bytes(b"data")
    with pytest.raises(ValueError, match="different file"):
        encrypt_file(plain, plain, "pw")
    assert plain.read_bytes() == b"data"


def test_missing_source_file_raises_and_leaves_nothing_behind(tmp_path):
    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "nope.bin", tmp_path / "out.ctk", "pw")
    assert list(tmp_path.iterdir()) == []


def test_no_temporary_file_is_left_after_success(tmp_path):
    round_trip(tmp_path, b"data")
    assert not list(tmp_path.glob("*.part"))