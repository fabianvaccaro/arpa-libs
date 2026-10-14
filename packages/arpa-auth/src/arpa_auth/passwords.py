"""Password hashing: Argon2id for new hashes, verification of legacy PBKDF2-SHA256 hashes.

New hashes are always Argon2id. ``verify`` also accepts the PBKDF2-SHA256 formats that already
exist in our services, so a service can switch to this module without resetting passwords:
verify, and when ``needs_rehash`` is true, store ``hash(password)`` in place of the old value.

Accepted stored formats:

- ``$argon2id$...`` (and ``$argon2i$`` / ``$argon2d$``): the PHC string from argon2-cffi.
- ``pbkdf2_sha256$<iterations>$<salt hex>$<hash hex>``.
- A mapping ``{"iterations": int, "salt": <hex>, "hash": <hex>}`` (optionally with
  ``"algorithm": "pbkdf2_sha256"``), the shape some services keep in a document store.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any, NamedTuple

import argon2
from argon2.exceptions import InvalidHashError, VerificationError

# Hashing cost grows with the input; refuse absurd inputs before doing any work.
MAX_PASSWORD_LENGTH = 1024
PBKDF2_PREFIX = "pbkdf2_sha256"


class Verification(NamedTuple):
    ok: bool
    needs_rehash: bool


_FAILED = Verification(False, False)


class PasswordHasher:
    """Argon2id hasher. Defaults follow OWASP's first Argon2id profile (64 MiB, t=3, p=4).

    The instance is stateless and safe to share; build one at startup.
    """

    def __init__(self, *, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4) -> None:
        self._ph = argon2.PasswordHasher(
            time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, type=argon2.Type.ID
        )

    def hash(self, password: str) -> str:
        _check_length(password)
        return self._ph.hash(password)

    def verify(self, password: str, stored: str | Mapping[str, Any]) -> Verification:
        """Check ``password`` against ``stored``. Never raises for a wrong password or a malformed hash.

        ``needs_rehash`` is true when the password is right but ``stored`` is a legacy format or uses
        weaker Argon2 parameters than this hasher.
        """
        if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
            return _FAILED
        if isinstance(stored, Mapping):
            return _verify_pbkdf2_mapping(password, stored)
        if not isinstance(stored, str):
            return _FAILED
        if stored.startswith("$argon2"):
            try:
                self._ph.verify(stored, password)
            except (VerificationError, InvalidHashError, ValueError):
                return _FAILED
            return Verification(True, self._ph.check_needs_rehash(stored))
        if stored.startswith(PBKDF2_PREFIX + "$"):
            parts = stored.split("$")
            if len(parts) != 4:
                return _FAILED
            return _verify_pbkdf2(password, parts[1], parts[2], parts[3])
        return _FAILED


def _check_length(password: str) -> None:
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password longer than {MAX_PASSWORD_LENGTH} characters")


def _verify_pbkdf2_mapping(password: str, record: Mapping[str, Any]) -> Verification:
    if record.get("algorithm", PBKDF2_PREFIX) != PBKDF2_PREFIX:
        return _FAILED
    try:
        return _verify_pbkdf2(password, record["iterations"], record["salt"], record["hash"])
    except KeyError:
        return _FAILED


def _verify_pbkdf2(password: str, iterations: Any, salt_hex: Any, hash_hex: Any) -> Verification:
    try:
        rounds = int(iterations)
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
    except (TypeError, ValueError):
        return _FAILED
    if rounds < 1 or not salt or not expected:
        return _FAILED
    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds, dklen=len(expected))
    if not hmac.compare_digest(got, expected):
        return _FAILED
    return Verification(True, True)
