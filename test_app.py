import threading
import time
import tkinter as tk

import pytest

import app as app_module
from app import MONO_FONT, ToolkitApp

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def select_tab(window, name):
    for index in range(window.notebook.index("end")):
        if window.notebook.tab(index, "text") == name:
            window.notebook.select(index)
            return
    raise AssertionError(f"no tab called {name}")


def press(window, sequence):
    window._shortcuts[sequence](None)


def finish_background(window, timeout=5):
    """Let the window's event loop run until the background task is done."""
    deadline = time.monotonic() + timeout
    while window._busy:
        window.update()
        if time.monotonic() > deadline:
            raise AssertionError("background task did not finish in time")
        time.sleep(0.01)


@pytest.fixture(scope="session")
def shared_window():
    # One window for the whole run: opening dozens of Tk windows in a row can
    # fail on Windows, so the tests reuse this one and reset it each time.
    try:
        win = ToolkitApp()
    except tk.TclError as error:
        if "display" in str(error):
            pytest.skip("no display available")
        raise
    win.withdraw()
    yield win
    win.destroy()


@pytest.fixture
def window(shared_window, monkeypatch):
    win = shared_window
    finish_background(win)
    win.on_clear_hash()
    win.on_clear_verify()
    win.on_clear_encrypt()
    win.on_clear_passwords()
    win.notebook.select(0)
    for variable, value in (
        (win.hash_algorithm, "sha256"),
        (win.verify_algorithm, "sha256"),
        (win.show_password, False),
        (win.show_check, False),
        (win.generate_length, "16"),
        (win.use_symbols, True),
    ):
        variable.set(value)
    win._toggle_password()
    win._toggle_check_password()
    errors = []
    monkeypatch.setattr(
        app_module.messagebox, "showerror", lambda title, message: errors.append((title, message))
    )
    win.errors = errors
    return win


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


def test_hash_text_with_md5(window):
    window.hash_input.insert("1.0", "abc")
    window.hash_algorithm.set("md5")
    window.on_hash_text()
    assert window.hash_output.get() == "900150983cd24fb0d6963f7d28e17f72"


def test_legacy_note_shows_only_for_md5_and_sha1(window):
    for tab_variable, note in (
        (window.hash_algorithm, window.hash_note),
        (window.verify_algorithm, window.verify_note),
    ):
        assert note.cget("text") == ""
        for legacy in ("md5", "sha1"):
            tab_variable.set(legacy)
            assert "Not secure" in note.cget("text")
        for modern in ("sha512", "sha256"):
            tab_variable.set(modern)
            assert note.cget("text") == ""


def test_hash_text_empty_shows_popup(window):
    window.on_hash_text()
    assert window.errors[-1][0] == "Cannot hash"


def test_hash_file_shows_result(window, tmp_path, monkeypatch):
    choose_file(monkeypatch, make_file(tmp_path, "a.txt", b"abc"))
    window.on_hash_file()
    finish_background(window)
    assert window.hash_output.get() == ABC_SHA256


def test_hash_file_cancelled_keeps_result(window, monkeypatch):
    choose_file(monkeypatch, "")
    window.hash_output.set("keep")
    window.on_hash_file()
    assert window.hash_output.get() == "keep"


def test_hash_file_unreadable_shows_popup(window, tmp_path, monkeypatch):
    choose_file(monkeypatch, tmp_path / "missing.txt")
    window.on_hash_file()
    finish_background(window)
    assert window.errors[-1][0] == "Cannot read file"


def test_hash_file_runs_in_background(window, tmp_path, monkeypatch):
    gate = threading.Event()

    def slow_hash_file(path, algorithm):
        gate.wait(timeout=5)
        return "slow-result"

    monkeypatch.setattr(app_module, "hash_file", slow_hash_file)
    choose_file(monkeypatch, make_file(tmp_path, "a.txt", b"abc"))
    window.on_hash_file()

    # the handler returned while the work is still running
    assert window._busy is True
    assert window.status_label.cget("text") == "Hashing file..."
    assert window.progress.winfo_manager() == "pack"
    assert window.hash_output.get() == ""
    for button in (window.hash_file_button, window.compare_button, window.check_button):
        assert str(button.cget("state")) == "disabled"

    gate.set()
    finish_background(window)
    assert window.hash_output.get() == "slow-result"
    assert window.status_label.cget("text") == "Ready"
    assert window.progress.winfo_manager() == ""
    for button in (window.hash_file_button, window.compare_button, window.check_button):
        assert str(button.cget("state")) == "normal"


def test_inputs_use_the_normal_font_and_encrypted_output_is_monospaced(window):
    assert str(window.hash_input.cget("font")) == "TkDefaultFont"
    assert str(window.encrypt_input.cget("font")) == "TkDefaultFont"
    assert str(window.encrypt_output.cget("font")) == MONO_FONT


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
    finish_background(window)
    assert "identical" in window.verify_result.cget("text")


def test_compare_different_files(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.file2.set(str(make_file(tmp_path, "b.bin", b"diff")))
    window.on_compare()
    finish_background(window)
    assert "differ" in window.verify_result.cget("text")


def test_compare_needs_both_files(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.on_compare()
    assert window.errors[-1][0] == "Missing file"


def test_compare_missing_file_shows_popup(window, tmp_path):
    window.file1.set(str(make_file(tmp_path, "a.bin", b"same")))
    window.file2.set(str(tmp_path / "nope.bin"))
    window.on_compare()
    finish_background(window)
    assert window.errors[-1][0] == "Cannot read file"


def test_check_hash_matches_ignoring_case(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.expected_hash.set(ABC_SHA256.upper())
    window.on_check_hash()
    finish_background(window)
    assert "intact" in window.verify_result.cget("text")


def test_check_hash_mismatch(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.expected_hash.set("0" * 64)
    window.on_check_hash()
    finish_background(window)
    assert "NOT" in window.verify_result.cget("text")


def test_check_hash_empty_hash_shows_popup(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.on_check_hash()
    finish_background(window)
    assert window.errors[-1][0] == "Cannot check file"


def test_check_hash_needs_file(window):
    window.on_check_hash()
    assert window.errors[-1][0] == "Missing file"


def test_pasting_a_hash_picks_the_algorithm(window):
    window.expected_hash.set("900150983cd24fb0d6963f7d28e17f72")
    assert window.verify_algorithm.get() == "md5"
    assert "md5" in window.detected_label.cget("text")
    window.expected_hash.set(ABC_SHA256)
    assert window.verify_algorithm.get() == "sha256"
    assert "sha256" in window.detected_label.cget("text")


def test_unrecognised_hash_keeps_the_chosen_algorithm(window):
    window.verify_algorithm.set("sha512")
    window.expected_hash.set("abc123")
    assert window.verify_algorithm.get() == "sha512"
    assert window.detected_label.cget("text") == ""


def test_detected_label_clears_when_algorithm_is_changed_by_hand(window):
    window.expected_hash.set(ABC_SHA256)
    assert "sha256" in window.detected_label.cget("text")
    window.verify_algorithm.set("md5")
    assert window.detected_label.cget("text") == ""


def test_check_file_against_md5_hash_with_auto_detection(window, tmp_path):
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.expected_hash.set("900150983CD24FB0D6963F7D28E17F72")
    window.on_check_hash()
    finish_background(window)
    assert "intact" in window.verify_result.cget("text")


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


def test_weak_encrypt_password_shows_a_warning(window):
    window.encrypt_password.set("password")
    text = window.password_strength.cget("text")
    assert text.startswith("Very weak password.")
    assert "top-10" in text


def test_strong_encrypt_password_shows_no_warning(window):
    window.encrypt_password.set("xk9#Lm2$Qp7!vR4z")
    text = window.password_strength.cget("text")
    assert text == "Very strong password."


def test_encrypt_password_note_clears_when_empty(window):
    window.encrypt_password.set("password")
    window.encrypt_password.set("")
    assert window.password_strength.cget("text") == ""


def test_weak_password_warns_but_does_not_block_encryption(window):
    window.encrypt_input.insert("1.0", "secret")
    window.encrypt_password.set("pw")
    window.on_encrypt()
    assert "weak" in window.password_strength.cget("text").lower()
    assert encrypted_output(window) != ""
    assert window.errors == []


def test_clear_encrypt_also_clears_the_password_note(window):
    window.encrypt_password.set("password")
    window.on_clear_encrypt()
    assert window.password_strength.cget("text") == ""


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




# ---------- Keyboard shortcuts ----------
def test_ctrl_enter_hashes_text_on_the_hash_tab(window):
    window.hash_input.insert("1.0", "abc")
    press(window, "<Control-Return>")
    assert window.hash_output.get() == ABC_SHA256


def test_ctrl_enter_checks_the_file_on_the_verify_tab(window, tmp_path):
    select_tab(window, "Verify")
    window.check_file.set(str(make_file(tmp_path, "a.txt", b"abc")))
    window.expected_hash.set(ABC_SHA256)
    press(window, "<Control-Return>")
    finish_background(window)
    assert "intact" in window.verify_result.cget("text")


def test_ctrl_enter_encrypts_and_ctrl_shift_enter_decrypts(window):
    select_tab(window, "Encrypt")
    window.encrypt_input.insert("1.0", "secret")
    window.encrypt_password.set("xk9#Lm2$Qp7!vR4z")
    press(window, "<Control-Return>")
    package = encrypted_output(window)
    assert package != ""

    window.encrypt_input.delete("1.0", "end")
    window.encrypt_input.insert("1.0", package)
    press(window, "<Control-Shift-Return>")
    assert encrypted_output(window) == "secret"


def test_ctrl_enter_generates_a_password_on_the_passwords_tab(window):
    select_tab(window, "Passwords")
    press(window, "<Control-Return>")
    assert len(window.generated_password.get()) == 16


def test_decrypt_shortcut_does_nothing_outside_the_encrypt_tab(window):
    window.hash_input.insert("1.0", "abc")
    press(window, "<Control-Shift-Return>")
    assert window.hash_output.get() == ""
    assert window.errors == []


def test_ctrl_l_clears_only_the_current_tab(window):
    window.hash_input.insert("1.0", "abc")
    window.encrypt_input.insert("1.0", "keep me")
    press(window, "<Control-l>")
    assert window.hash_input.get("1.0", "end-1c") == ""
    assert window.encrypt_input.get("1.0", "end-1c") == "keep me"


def test_ctrl_shift_c_copies_the_result(window):
    window.hash_output.set("deadbeef")
    press(window, "<Control-Shift-C>")
    assert window.clipboard_get() == "deadbeef"


def test_ctrl_number_switches_tabs(window):
    for number, name in enumerate(("Hash", "Verify", "Encrypt", "Passwords")):
        window._select_tab(number)
        assert window.notebook.tab(window.notebook.select(), "text") == name


def test_shortcuts_are_bound_on_the_window_and_text_boxes(window):
    for sequence in window._shortcuts:
        assert window.bind(sequence)
    for number in range(1, 5):
        assert window.bind(f"<Control-Key-{number}>")
    for sequence in ("<Control-Return>", "<Control-Shift-Return>"):
        assert window.bind_class("Text", sequence)