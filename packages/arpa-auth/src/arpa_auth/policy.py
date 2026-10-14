"""Password strength policy. Returns problem codes, not messages, so each service words them in
its own language."""

from __future__ import annotations

from .passwords import MAX_PASSWORD_LENGTH

TOO_SHORT, TOO_LONG, TOO_SIMPLE, CONTAINS_IDENTITY = (
    "too_short",
    "too_long",
    "too_simple",
    "contains_identity",
)


def password_problems(
    password: str, *, min_length: int = 12, min_classes: int = 3, identity: tuple[str, ...] = ()
) -> list[str]:
    """Empty list when ``password`` is acceptable.

    ``min_classes`` counts lowercase, uppercase, digits and other characters. ``identity`` holds
    values the password must not contain (user name, e-mail local part), compared case-insensitively
    and ignored when shorter than 4 characters.
    """
    problems = []
    if len(password) < min_length:
        problems.append(TOO_SHORT)
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(TOO_LONG)
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < min_classes:
        problems.append(TOO_SIMPLE)
    low = password.lower()
    if any(len(v) >= 4 and v.lower() in low for v in identity):
        problems.append(CONTAINS_IDENTITY)
    return problems
