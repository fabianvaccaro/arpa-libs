from datetime import UTC, datetime, timedelta

import pytest

from arpa_auth import OneTimeCode, digest, matches, new_token, password_problems
from arpa_auth.policy import CONTAINS_IDENTITY, TOO_LONG, TOO_SHORT, TOO_SIMPLE


def test_opaque_tokens():
    t = new_token()
    assert len(t) >= 43 and t != new_token()
    d = digest(t)
    assert len(d) == 64 and matches(t, d) and not matches(t + "x", d)
    assert not matches(None, d)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        new_token(8)


def test_one_time_code():
    now = datetime(2026, 10, 14, tzinfo=UTC)
    c = OneTimeCode.issue(ttl=timedelta(seconds=120), now=now)
    assert c.code not in repr(c)
    assert OneTimeCode.redeem(c.code, c.digest, c.expires_at, now=now + timedelta(seconds=119))
    assert not OneTimeCode.redeem(c.code, c.digest, c.expires_at, now=now + timedelta(seconds=120))
    assert not OneTimeCode.redeem("other", c.digest, c.expires_at, now=now)
    assert OneTimeCode.redeem(OneTimeCode.issue().code, digest("x"), datetime.now(UTC)) is False


def test_password_policy():
    assert password_problems("Correct-Horse-9") == []
    assert password_problems("short") == [TOO_SHORT, TOO_SIMPLE]
    assert TOO_LONG in password_problems("aA1-" * 300)
    assert password_problems("alllowercaseletters") == [TOO_SIMPLE]
    assert password_problems("Gustavo-2026-x", identity=("gustavo",)) == [CONTAINS_IDENTITY]
    assert password_problems("Gus-2026-xyzAB", identity=("gus",)) == []
