"""Signed JWT access and refresh tokens with key rotation.

The application builds one ``Keyring`` at startup (from its own settings/secrets; nothing here
reads the environment or the filesystem) and one ``TokenIssuer`` around it.

- Algorithms are pinned per key. A token whose header names another algorithm, or ``none``, is
  rejected before any signature check, so algorithm-confusion attacks don't apply.
- Rotation: sign with ``Keyring.current``; ``Keyring.previous`` keys still verify, so tokens issued
  before a rotation stay valid until they expire. Tokens carry the key id in the ``kid`` header.
- Every token has ``iss``, ``aud``, ``sub``, ``iat``, ``nbf``, ``exp``, ``jti`` and ``typ``
  (``access`` or ``refresh``). A refresh token is never accepted where an access token is expected.
- Refresh tokens carry a family id (``fid``). Rotate on every use: issue the new refresh token with
  the same family, store the new ``jti`` as the only live one of the family, and when a ``jti``
  that is not the live one comes back, revoke the whole family (it was stolen and replayed).
  Storage is the application's; this module stays stateless.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

SYMMETRIC = ("HS256", "HS384", "HS512")
ASYMMETRIC = ("ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "EdDSA")
ALGORITHMS = SYMMETRIC + ASYMMETRIC
MIN_SECRET_BYTES = 32
RESERVED_CLAIMS = frozenset({"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "typ", "fid"})
ACCESS, REFRESH = "access", "refresh"


class InvalidToken(Exception):
    """The token can't be trusted. ``reason`` is a short machine-readable code; the token itself is
    never included, so the exception is safe to log."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


@dataclass(frozen=True)
class SigningKey:
    """One key. ``signing`` is the HMAC secret or the private PEM; ``verifying`` defaults to the same
    secret (HS*) and must be the public PEM for asymmetric algorithms. A verify-only key (a service
    that only checks tokens) has ``signing=None``."""

    kid: str
    algorithm: str
    signing: str | bytes | None = field(default=None, repr=False)
    verifying: str | bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.algorithm not in ALGORITHMS:
            raise ValueError(f"unsupported algorithm {self.algorithm!r}; one of {', '.join(ALGORITHMS)}")
        if not self.kid:
            raise ValueError("kid must be non-empty")
        if self.algorithm in SYMMETRIC:
            secret = self.signing if self.signing is not None else self.verifying
            if secret is None:
                raise ValueError("HMAC keys need a secret")
            raw = secret.encode() if isinstance(secret, str) else secret
            if len(raw) < MIN_SECRET_BYTES:
                raise ValueError(f"HMAC secret shorter than {MIN_SECRET_BYTES} bytes")
            object.__setattr__(self, "verifying", secret)
        elif self.verifying is None:
            raise ValueError(f"{self.algorithm} keys need the public key in `verifying`")

    @classmethod
    def hmac(cls, secret: str | bytes, kid: str = "k1", algorithm: str = "HS256") -> SigningKey:
        return cls(kid, algorithm, signing=secret)


@dataclass(frozen=True)
class Keyring:
    current: SigningKey
    previous: tuple[SigningKey, ...] = ()

    def __post_init__(self) -> None:
        kids = [k.kid for k in self.all()]
        if len(set(kids)) != len(kids):
            raise ValueError("kids must be unique within a keyring")

    def all(self) -> tuple[SigningKey, ...]:
        return (self.current, *self.previous)

    def rotated(self, new: SigningKey, keep: int = 1) -> Keyring:
        """A keyring signing with ``new`` that still verifies the last ``keep`` keys."""
        return Keyring(new, self.all()[:keep])


@dataclass(frozen=True)
class IssuedToken:
    token: str = field(repr=False)
    jti: str
    expires_at: datetime
    family: str | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TokenIssuer:
    def __init__(
        self,
        keyring: Keyring,
        *,
        issuer: str,
        audience: str | Iterable[str],
        access_ttl: timedelta = timedelta(minutes=15),
        refresh_ttl: timedelta = timedelta(days=14),
        leeway: timedelta = timedelta(seconds=60),
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        self.keyring = keyring
        self.issuer = issuer
        self.audience = [audience] if isinstance(audience, str) else list(audience)
        if not self.audience:
            raise ValueError("audience is required")
        self.access_ttl, self.refresh_ttl, self.leeway, self._clock = access_ttl, refresh_ttl, leeway, clock

    # ------------------------------------------------------------------ issuing
    def issue_access(
        self, subject: str, claims: Mapping[str, Any] | None = None, ttl: timedelta | None = None
    ) -> IssuedToken:
        return self._issue(subject, ACCESS, ttl or self.access_ttl, claims)

    def issue_refresh(
        self, subject: str, family: str | None = None, ttl: timedelta | None = None
    ) -> IssuedToken:
        """New refresh token. Pass the ``family`` of the token being rotated; omit it at login."""
        return self._issue(subject, REFRESH, ttl or self.refresh_ttl, None, family or uuid.uuid4().hex)

    def _issue(
        self,
        subject: str,
        typ: str,
        ttl: timedelta,
        claims: Mapping[str, Any] | None,
        family: str | None = None,
    ) -> IssuedToken:
        if not subject:
            raise ValueError("subject is required")
        key = self.keyring.current
        if key.signing is None:
            raise ValueError(f"key {key.kid!r} is verify-only")
        if claims and (clash := RESERVED_CLAIMS & set(claims)):
            raise ValueError(f"reserved claims can't be overridden: {', '.join(sorted(clash))}")
        now = self._clock()
        exp, jti = now + ttl, uuid.uuid4().hex
        payload: dict[str, Any] = {
            **(claims or {}),
            "iss": self.issuer,
            "aud": self.audience[0] if len(self.audience) == 1 else self.audience,
            "sub": str(subject),
            "iat": now,
            "nbf": now,
            "exp": exp,
            "jti": jti,
            "typ": typ,
        }
        if family:
            payload["fid"] = family
        token = jwt.encode(payload, key.signing, algorithm=key.algorithm, headers={"kid": key.kid})
        return IssuedToken(token, jti, exp, family)

    # ------------------------------------------------------------------ verifying
    def decode(self, token: str, expected_type: str = ACCESS) -> dict[str, Any]:
        """Verify ``token`` and return its claims, or raise ``InvalidToken``."""
        if not isinstance(token, str) or not token:
            raise InvalidToken("malformed")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as e:
            raise InvalidToken("malformed") from e
        alg, kid = header.get("alg"), header.get("kid")
        candidates = [k for k in self.keyring.all() if (kid is None or k.kid == kid)]
        if not candidates:
            raise InvalidToken("unknown_key", str(kid))
        candidates = [k for k in candidates if k.algorithm == alg]
        if not candidates:
            raise InvalidToken("bad_algorithm", str(alg))
        # PyJWT checks the time claims against the wall clock; with an injected clock we check them.
        own_clock = self._clock is not _utcnow
        options: dict[str, Any] = {"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]}
        if own_clock:
            options.update(verify_exp=False, verify_nbf=False, verify_iat=False)
        last: InvalidToken | None = None
        for key in candidates:
            try:
                claims = jwt.decode(
                    token,
                    key.verifying,
                    algorithms=[key.algorithm],
                    audience=self.audience,
                    issuer=self.issuer,
                    leeway=self.leeway,
                    options=options,
                )
            except jwt.InvalidSignatureError as e:
                last = InvalidToken("bad_signature")
                last.__cause__ = e
                continue
            except jwt.ExpiredSignatureError as e:
                raise InvalidToken("expired") from e
            except jwt.ImmatureSignatureError as e:
                raise InvalidToken("not_yet_valid") from e
            except jwt.InvalidAudienceError as e:
                raise InvalidToken("wrong_audience") from e
            except jwt.InvalidIssuerError as e:
                raise InvalidToken("wrong_issuer") from e
            except jwt.MissingRequiredClaimError as e:
                raise InvalidToken("missing_claim", e.claim) from e
            except jwt.PyJWTError as e:
                raise InvalidToken("malformed") from e
            if own_clock:
                self._check_times(claims)
            if claims.get("typ") != expected_type:
                raise InvalidToken("wrong_type", f"expected {expected_type}")
            if expected_type == REFRESH and not claims.get("fid"):
                raise InvalidToken("missing_claim", "fid")
            return claims
        raise last or InvalidToken("bad_signature")

    def _check_times(self, claims: Mapping[str, Any]) -> None:
        now = self._clock().timestamp()
        slack = self.leeway.total_seconds()
        if claims["exp"] <= now - slack:
            raise InvalidToken("expired")
        if claims["nbf"] > now + slack or claims["iat"] > now + slack:
            raise InvalidToken("not_yet_valid")
