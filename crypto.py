import base64
import os
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
SCRYPT_N = 2**15
FILE_MAGIC = b"CTKF"
FILE_VERSION = 1
FILE_CHUNK_SIZE = 1024 * 1024
NONCE_PREFIX_SIZE = 7
FILE_HEADER_SIZE = len(FILE_MAGIC) + 1 + 4 + SALT_SIZE + NONCE_PREFIX_SIZE


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_text(plaintext: str, password: str) -> str:
    if not plaintext:
        raise ValueError("Please enter some text first.")
    if not password:
        raise ValueError("Please enter a password first.")
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + nonce + ciphertext).decode("ascii")


def decrypt_text(package: str, password: str) -> str:
    if not package.strip():
        raise ValueError("Please paste the encrypted text first.")
    if not password:
        raise ValueError("Please enter a password first.")
    try:
        raw = base64.b64decode("".join(package.split()), validate=True)
    except ValueError:
        raise ValueError("This doesn't look like encrypted text.") from None
    if len(raw) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("This doesn't look like encrypted text.")
    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE:]
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong password, or the encrypted text was changed.") from None
    return plaintext.decode("utf-8")


# ---------- File encryption ----------
# File layout: a 32-byte header (magic "CTKF", version, chunk size, salt, nonce
# prefix) followed by the data in chunks, each sealed with AES-GCM. A chunk's
# nonce is the prefix + its position + a "last chunk" flag, and the header is
# authenticated with every chunk, so reordered, cut-off or edited files fail.


def _chunk_nonce(prefix: bytes, index: int, is_last: bool) -> bytes:
    return prefix + index.to_bytes(4, "big") + (b"\x01" if is_last else b"\x00")


def _check_file_arguments(source, destination, password: str) -> None:
    if not password:
        raise ValueError("Please enter a password first.")
    if Path(source).resolve() == Path(destination).resolve():
        raise ValueError("Choose a different file to save to.")


def _write_through_temp_file(source, destination, write_chunks) -> None:
    # Write to a temporary file first, so a failed or wrong-password attempt
    # never leaves a half-written file (or overwrites an existing one)
    destination = Path(destination)
    temp = destination.with_name(destination.name + ".part")
    try:
        with open(source, "rb") as src, open(temp, "wb") as out:
            write_chunks(src, out)
        os.replace(temp, destination)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def encrypt_file(source, destination, password: str) -> None:
    _check_file_arguments(source, destination, password)
    salt = secrets.token_bytes(SALT_SIZE)
    prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
    header = (
        FILE_MAGIC
        + bytes([FILE_VERSION])
        + FILE_CHUNK_SIZE.to_bytes(4, "big")
        + salt
        + prefix
    )
    aes = AESGCM(_derive_key(password, salt))

    def write_chunks(src, out):
        out.write(header)
        chunk = src.read(FILE_CHUNK_SIZE)
        index = 0
        while True:
            following = src.read(FILE_CHUNK_SIZE)
            is_last = not following
            out.write(aes.encrypt(_chunk_nonce(prefix, index, is_last), chunk, header))
            if is_last:
                break
            chunk, index = following, index + 1

    _write_through_temp_file(source, destination, write_chunks)


def decrypt_file(source, destination, password: str) -> None:
    _check_file_arguments(source, destination, password)

    def write_chunks(src, out):
        header = src.read(FILE_HEADER_SIZE)
        if len(header) < FILE_HEADER_SIZE or not header.startswith(FILE_MAGIC):
            raise ValueError("This doesn't look like a file encrypted by this app.")
        if header[4] != FILE_VERSION:
            raise ValueError("This file was made by a newer version of the app.")
        if int.from_bytes(header[5:9], "big") != FILE_CHUNK_SIZE:
            raise ValueError("This doesn't look like a file encrypted by this app.")
        salt = header[9:9 + SALT_SIZE]
        prefix = header[9 + SALT_SIZE:]
        aes = AESGCM(_derive_key(password, salt))
        sealed_size = FILE_CHUNK_SIZE + TAG_SIZE
        chunk = src.read(sealed_size)
        index = 0
        while True:
            following = src.read(sealed_size)
            is_last = not following
            try:
                out.write(aes.decrypt(_chunk_nonce(prefix, index, is_last), chunk, header))
            except InvalidTag:
                raise ValueError("Wrong password, or the file was changed.") from None
            if is_last:
                break
            chunk, index = following, index + 1

    _write_through_temp_file(source, destination, write_chunks)