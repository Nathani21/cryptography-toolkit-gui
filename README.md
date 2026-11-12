# Cryptography Toolkit GUI

![Tests](https://github.com/Nathani21/cryptography-toolkit-gui/actions/workflows/tests.yml/badge.svg)

A small Python desktop app (Tkinter) for hashing text and files, checking file integrity, encrypting text with a password, and checking password strength. Everything runs on your computer; nothing is sent anywhere.

> **Note:** This is a learning project and has not been audited. It uses standard algorithms from the `cryptography` library (AES-256-GCM and scrypt), but don't rely on it to protect anything important. The SHA hashes are for checking file integrity; they are not a way to store passwords.

## Features

**Hash**
- SHA-256 or SHA-512 of typed text or any file
- Copy the result, or clear the tab

**Verify**
- Compare two files to see whether they are identical
- Check a file against a hash you paste in, such as one published next to a download (case and spaces are ignored)

**Encrypt**
- Encrypt text with a password, then paste the result back in to decrypt it
- A wrong password, or text that was changed, is detected and reported
- A lost password cannot be recovered

**Passwords**
- Live strength meter while you type, with warnings and suggestions
- Password generator: length 8 to 128, optional symbols

## Run from source

Developed and tested on Windows 11 with Python 3.13. Tkinter ships with Python on Windows.

```
git clone https://github.com/Nathani21/cryptography-toolkit-gui.git
cd cryptography-toolkit-gui
pip install -r requirements.txt
python app.py
```

## How it works

| File | Purpose |
|---|---|
| `app.py` | The window and its four tabs |
| `hashing.py` | Text and file hashing, file comparison |
| `crypto.py` | Password-based encryption and decryption |
| `passwords.py` | Strength checking (zxcvbn) and password generation |
| `test_*.py` | pytest tests for the three logic modules |

The logic modules know nothing about the window, so they can be tested on their own.

Encryption uses AES-256-GCM. The key is derived from your password with scrypt and a random salt. The output is one Base64 string holding the salt, the nonce and the ciphertext.

## Run the tests

```
pip install pytest
python -m pytest
```

The GUI itself is not covered by the tests.

## License

MIT. See [LICENSE](LICENSE).