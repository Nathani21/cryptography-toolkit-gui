import secrets
import string
from typing import NamedTuple

from zxcvbn import zxcvbn

LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")
MAX_CHECK_LENGTH = 72
MIN_LENGTH = 8
MAX_LENGTH = 128
SYMBOLS = "!@#$%^&*()-_=+"


class StrengthResult(NamedTuple):
    score: int
    label: str
    warning: str
    suggestions: list


def check_strength(password: str) -> StrengthResult:
    if not password:
        raise ValueError("Please enter a password first.")
    # zxcvbn raises an error above 72 characters, so only the start is analysed
    result = zxcvbn(password[:MAX_CHECK_LENGTH])
    score = result["score"]
    feedback = result["feedback"]
    return StrengthResult(
        score=score,
        label=LABELS[score],
        warning=feedback["warning"],
        suggestions=list(feedback["suggestions"]),
    )


def generate_password(length: int = 16, symbols: bool = True) -> str:
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        groups.append(SYMBOLS)
    chars = [secrets.choice(group) for group in groups]
    pool = "".join(groups)
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)