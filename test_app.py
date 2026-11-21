import hashlib
import tkinter as tk

import pytest

import app as app_module
from app import ToolkitApp

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@pytest.fixture
def window(monkeypatch):
    try:
        win = ToolkitApp()
    except tk.TclError:
        pytest.skip("no display available")
    win.withdraw()
    errors = []
    monkeypatch.setattr(
        app_module.messagebox, "showerror", lambda title, message: errors.append((title, message))
    )
    win.errors = errors
    yield win
    win.destroy()


def choose_file(monkeypatch, path):
    monkeypatch.setattr(app_module.filedialog, "askopenfilename", lambda **kwargs: str(path))


def make_file(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)
    return path


# ---------- Hash tab ----------
def test_hash_text_shows_result(window):
    window.hash_input.insert("1.0", "abc")
    window.on_hash_text()
    assert window.hash_output.get() == ABC_SHA256


def test_hash_text_uses_chosen_algorithm(window):
    window.hash_input.insert("1.0", "abc")
    window.hash_algorithm.set("sha512")
    window.on_hash_text()
    assert len(window.hash_output.get()) == 128


def test_hash_text_empty_shows_popup(window):
    window.on_hash_text()
    assert window.errors[-1][0] == "Cannot hash"


def test_hash_file_shows_result(window, tmp_path, monkeypatch):
    choose_file(monkeypatch, make_file(tmp_path, "a.txt", b"abc"))
    window.on_hash_file()
    assert window.hash_output.get() == ABC_SHA256


def test_hash_file_cancelled_keeps_result(window, monkeypatch):
    choose_file(monkeypatch, "")
    window.hash_output.set("keep")
    window.on_hash_file()
    assert window.hash_output.get() == "keep"


def test_hash_file_unreadable_shows_popup(window, tmp_path, monkeypatch):
    choose_file(monkeypatch, tmp_path / "missing.txt")
    window.on_hash_file()
    assert window.errors[-1][0] == "Cannot read file"


def test_copy_hash_puts_result_on_clipboard(window):
    window.hash_output.set("deadbeef")
    window.on_copy_hash()
    assert window.clipboard_get() == "deadbeef"


def test_clear_hash_empties_everything(window):
    window.hash_input.insert("1.0", "abc")
    window.on_hash_text()
    window.on_clear_hash()
    assert window.hash_input.get("1.0", "end-1c") == ""
    assert window.hash_output.get() == ""


# ---------- Verify tab ----------
def test_compare_identical_files(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.file2.set(str(make_file(tmp_path, "b.bin", b"same")))
    window.on_compare()
    assert "identical" in window.verify_result.cget("text")


def test_compare_different_files(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.file2.set(str(make_file(tmp_path, "b.bin", b"diff")))
    window.on_compare()
    assert "differ" in window.verify_result.cget("text")


def test_compare_needs_both_files(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.on_compare()
    assert window.errors[-1][0] == "Missing file"


def test_compare_missing_file_shows_popup(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.file2.set(str(tmp_path / "nope.bin"))
    window.on_compare()
    assert window.errors[-1][0] == "Cannot read file"


def test_check_hash_matches_ignoring_case(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.expected_hash.set(ABC_SHA256.upper())
    window.on_check_hash()
    assert "intact" in window.verify_result.cget("text")


def test_check_hash_mismatch(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.expected_hash.set("0" * 64)
    window.on_check_hash()
    assert "NOT" in window.verify_result.cget("text")


def test_check_hash_empty_hash_shows_popup(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.on_check_hash()
    assert window.errors[-1][0] == "Cannot check file"


def test_check_hash_needs_file(window):
    window.on_check_hash()
    assert window.errors[-1][0] == "Missing file"


def test_clear_verify_empties_everything(window, tmp_path):
    window.file1.set("x")
    window.expected_hash.set("h")
    window.verify_result.config(text="something")
    window.on_clear_verify()
    assert window.file1.get() == ""
    assert window.expected_hash.get() == ""
    assert window.verify_result.cget("text") == ""


# ---------- Encrypt tab ----------
def encrypted_output(window):
    return window.encrypt_output.get("1.0", "end-1c")


def test_encrypt_then_decrypt_round_trip(window):
    window.encrypt_input.insert("1.0", "héllo ₦aira")
    window.encrypt_password.set("pw123")
    window.on_encrypt()
    package = encrypted_output(window)
    assert package and package != "héllo ₦aira"

    window.encrypt_input.delete("1.0", "end")
    window.encrypt_input.insert("1.0", package)
    window.on_decrypt()
    assert encrypted_output(window) == "héllo ₦aira"


def test_encrypt_without_password_shows_popup(window):
    window.encrypt_input.insert("1.0", "secret")
    window.on_encrypt()
    assert window.errors[-1][0] == "Cannot encrypt"


def test_decrypt_wrong_password_shows_popup(window):
    window.encrypt_input.insert("1.0", "secret")
    window.encrypt_password.set("right")
    window.on_encrypt()
    package = encrypted_output(window)
    window.encrypt_input.delete("1.0", "end")
    window.encrypt_input.insert("1.0", package)
    window.encrypt_password.set("wrong")
    window.on_decrypt()
    assert window.errors[-1][0] == "Cannot decrypt"
    assert "Wrong password" in window.errors[-1][1]


def test_result_box_is_read_only(window):
    window.encrypt_input.insert("1.0", "secret")
    window.encrypt_password.set("pw")
    window.on_encrypt()
    assert str(window.encrypt_output.cget("state")) == "disabled"


def test_show_password_toggle(window):
    assert window.password_entry.cget("show") == "*"
    window.show_password.set(True)
    window._toggle_password()
    assert window.password_entry.cget("show") == ""
    window.show_password.set(False)
    window._toggle_password()
    assert window.password_entry.cget("show") == "*"


def test_clear_encrypt_empties_everything(window):
    window.encrypt_input.insert("1.0", "secret")
    window.encrypt_password.set("pw")
    window.on_encrypt()
    window.on_clear_encrypt()
    assert window.encrypt_input.get("1.0", "end-1c") == ""
    assert window.encrypt_password.get() == ""
    assert encrypted_output(window) == ""
    assert str(window.encrypt_output.cget("state")) == "disabled"


# ---------- Passwords tab ----------
def test_strength_meter_updates_while_typing(window):
    window.check_password.set("password")
    assert "Very weak" in window.strength_label.cget("text")
    assert float(window.strength_bar["value"]) == 1.0
    assert "top-10" in window.strength_feedback.cget("text")


def test_strength_meter_for_strong_password(window):
    window.check_password.set("xk9#Lm2$Qp7!vR4z")
    assert "Very strong" in window.strength_label.cget("text")
    assert float(window.strength_bar["value"]) == 5.0


def test_strength_meter_survives_very_long_input(window):
    window.check_password.set("a" * 200)
    assert "Strength:" in window.strength_label.cget("text")


def test_strength_meter_resets_when_empty(window):
    window.check_password.set("password")
    window.check_password.set("")
    assert window.strength_label.cget("text") == ""
    assert float(window.strength_bar["value"]) == 0.0


def test_generate_default_length(window):
    window.on_generate()
    assert len(window.generated_password.get()) == 16


def test_generate_without_symbols(window):
    window.generate_length.set("40")
    window.use_symbols.set(False)
    window.on_generate()
    password = window.generated_password.get()
    assert len(password) == 40 and password.isalnum()


@pytest.mark.parametrize("bad_length", ["abc", "5", "999"])
def test_generate_bad_length_shows_popup(window, bad_length):
    window.generate_length.set(bad_length)
    window.on_generate()
    assert window.errors[-1][0] == "Cannot generate"


def test_copy_generated_password(window):
    window.generated_password.set("copyme")
    window.on_copy_generated()
    assert window.clipboard_get() == "copyme"


def test_clear_passwords_empties_everything(window):
    window.check_password.set("abc")
    window.generated_password.set("zzz")
    window.on_clear_passwords()
    assert window.check_password.get() == ""
    assert window.generated_password.get() == ""
    assert window.strength_label.cget("text") == ""