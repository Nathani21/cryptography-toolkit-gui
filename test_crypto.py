import base64

import pytest

from crypto import decrypt_text, encrypt_text


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