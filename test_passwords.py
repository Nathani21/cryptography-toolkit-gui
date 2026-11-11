import string

import pytest

from passwords import SYMBOLS, check_strength, generate_password


def test_common_password_is_very_weak():
    result = check_strength("password")
    assert result.score == 0
    assert result.label == "Very weak"
    assert result.warning != ""
    assert result.suggestions != []


def test_strong_password_scores_high():
    result = check_strength("xk9#Lm2$Qp7!vR4z")
    assert result.score >= 3
    assert result.label in ("Strong", "Very strong")


def test_passphrase_scores_high():
    assert check_strength("correct horse battery staple").score >= 3


def test_check_strength_empty_raises():
    with pytest.raises(ValueError):
        check_strength("")


def test_check_strength_handles_very_long_input():
    result = check_strength("a" * 5000)
    assert 0 <= result.score <= 4


def test_generate_default_length():
    assert len(generate_password()) == 16


def test_generate_custom_length():
    assert len(generate_password(length=32)) == 32


def test_generate_contains_every_character_group():
    for _ in range(50):
        pw = generate_password(length=8)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_generate_without_symbols_is_alphanumeric():
    for _ in range(50):
        assert generate_password(symbols=False).isalnum()


def test_generate_rejects_bad_length():
    with pytest.raises(ValueError):
        generate_password(length=7)
    with pytest.raises(ValueError):
        generate_password(length=129)


def test_generated_passwords_differ():
    assert generate_password() != generate_password()


def test_generated_passwords_are_strong():
    for _ in range(20):
        assert check_strength(generate_password()).score >= 3