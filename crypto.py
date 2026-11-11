import base64
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
SCRYPT_N = 2**15


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