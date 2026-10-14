import hashlib
import secrets

import pytest

from arpa_auth import PasswordHasher
from arpa_auth.passwords import MAX_PASSWORD_LENGTH

FAST = {"time_cost": 1, "memory_cost": 8, "parallelism": 1}


def pbkdf2(password: str, iterations: int = 1000) -> tuple[int, str, str]:
    salt = secrets.token_bytes(16)
    return iterations, salt.hex(), hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations).hex()


def test_argon2_roundtrip():
    ph = PasswordHasher(**FAST)
    h = ph.hash("correct horse")
    assert h.startswith("$argon2id$")
    assert ph.verify("correct horse", h) == (True, False)
    assert ph.verify("wrong", h) == (False, False)


def test_weaker_params_need_rehash():
    old = PasswordHasher(**FAST).hash("pw")
    assert PasswordHasher(time_cost=2, memory_cost=16, parallelism=1).verify("pw", old) == (True, True)


def test_pbkdf2_string_format():
    it, salt, h = pbkdf2("legacy")
    stored = f"pbkdf2_sha256${it}${salt}${h}"
    ph = PasswordHasher(**FAST)
    assert ph.verify("legacy", stored) == (True, True)
    assert ph.verify("nope", stored) == (False, False)


def test_pbkdf2_mapping_format():
    it, salt, h = pbkdf2("legacy")
    ph = PasswordHasher(**FAST)
    assert ph.verify("legacy", {"iterations": it, "salt": salt, "hash": h}) == (True, True)
    assert ph.verify("legacy", {"algorithm": "pbkdf2_sha256", "iterations": it, "salt": salt, "hash": h}).ok
    assert not ph.verify("legacy", {"algorithm": "md5", "iterations": it, "salt": salt, "hash": h}).ok
    assert not ph.verify("legacy", {"iterations": it, "salt": salt}).ok


@pytest.mark.parametrize(
    "stored",
    [
        "",
        "plain",
        "$argon2id$garbage",
        "pbkdf2_sha256$x$00$00",
        "pbkdf2_sha256$1000$zz$00",
        "pbkdf2_sha256$0$00$00",
        "pbkdf2_sha256$1000$$",
        "pbkdf2_sha256$1000$00",
        None,
        42,
    ],
)
def test_malformed_never_raises(stored):
    assert PasswordHasher(**FAST).verify("pw", stored) == (False, False)


def test_length_limits():
    ph = PasswordHasher(**FAST)
    with pytest.raises(ValueError):
        ph.hash("x" * (MAX_PASSWORD_LENGTH + 1))
    with pytest.raises(TypeError):
        ph.hash(b"bytes")  # type: ignore[arg-type]
    assert not ph.verify("x" * (MAX_PASSWORD_LENGTH + 1), ph.hash("x")).ok
