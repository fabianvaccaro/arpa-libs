"""Opaque random tokens: session ids, API keys, one-time codes.

Hand the token to the client and store only ``digest(token)``: a leaked table yields nothing usable.
Lookups go by digest, so they need no constant-time comparison; ``matches`` is for the case where
the stored digest is fetched by another key (user id, code id) and compared in code.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

DEFAULT_BYTES = 32


def new_token(nbytes: int = DEFAULT_BYTES) -> str:
    """URL-safe random token with ``nbytes`` of entropy (at least 16)."""
    if nbytes < 16:
        raise ValueError("tokens need at least 16 bytes of entropy")
    return secrets.token_urlsafe(nbytes)


def digest(token: str) -> str:
    """SHA-256 hex digest to store server-side instead of the token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def matches(token: str, stored_digest: str) -> bool:
    """Constant-time check of ``token`` against a stored ``digest``."""
    if not isinstance(token, str) or not isinstance(stored_digest, str):
        return False
    return hmac.compare_digest(digest(token), stored_digest)


@dataclass(frozen=True)
class OneTimeCode:
    """A short-lived, single-use code (login link, launch code, e-mail confirmation).

    Store ``digest`` and ``expires_at``; send ``code``. On redemption call ``redeem`` and then
    delete the stored record in the same transaction, which is what makes it single-use.
    """

    code: str = field(repr=False)
    digest: str
    expires_at: datetime

    @classmethod
    def issue(
        cls, ttl: timedelta = timedelta(minutes=2), nbytes: int = DEFAULT_BYTES, now: datetime | None = None
    ) -> OneTimeCode:
        code = new_token(nbytes)
        return cls(code, digest(code), (now or datetime.now(UTC)) + ttl)

    @staticmethod
    def redeem(code: str, stored_digest: str, expires_at: datetime, now: datetime | None = None) -> bool:
        """True if ``code`` matches and hasn't expired."""
        return matches(code, stored_digest) and (now or datetime.now(UTC)) < expires_at
