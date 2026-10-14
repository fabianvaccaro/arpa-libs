import base64
import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from arpa_auth import ACCESS, REFRESH, InvalidToken, Keyring, SigningKey, TokenIssuer

SECRET = "s" * 32
T0 = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def issuer(keyring=None, clock=None, **kw):
    kw.setdefault("issuer", "arpa-test")
    kw.setdefault("audience", "arpa-api")
    if clock is not None:
        kw["clock"] = clock
    return TokenIssuer(keyring or Keyring(SigningKey.hmac(SECRET)), **kw)


def es256(kid="e1"):
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return SigningKey(kid, "ES256", signing=pem, verifying=pub), pub


def test_access_roundtrip_real_clock():
    ti = issuer()
    t = ti.issue_access("u1", {"roles": ["admin"], "tid": "t1"})
    c = ti.decode(t.token)
    assert (c["sub"], c["typ"], c["roles"], c["tid"], c["jti"]) == ("u1", ACCESS, ["admin"], "t1", t.jti)
    assert jwt.get_unverified_header(t.token)["kid"] == "k1"
    assert "token" not in repr(t)


def test_es256_and_verify_only_service():
    key, pub = es256()
    t = issuer(Keyring(key)).issue_access("u1")
    verifier = issuer(Keyring(SigningKey("e1", "ES256", verifying=pub)))
    assert verifier.decode(t.token)["sub"] == "u1"
    with pytest.raises(ValueError, match="verify-only"):
        verifier.issue_access("u1")


def test_rotation_keeps_old_tokens_until_dropped():
    old = SigningKey.hmac(SECRET, kid="k1")
    t = issuer(Keyring(old)).issue_access("u1")
    ring = Keyring(old).rotated(SigningKey.hmac("n" * 32, kid="k2"))
    assert issuer(ring).decode(t.token)["sub"] == "u1"
    assert jwt.get_unverified_header(issuer(ring).issue_access("u").token)["kid"] == "k2"
    with pytest.raises(InvalidToken) as e:
        issuer(ring.rotated(SigningKey.hmac("m" * 32, kid="k3"), keep=1)).decode(t.token)
    assert e.value.reason == "unknown_key"


def test_alg_none_rejected():
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    forged = f"{b64({'alg': 'none', 'kid': 'k1'})}.{b64({'sub': 'admin'})}."
    with pytest.raises(InvalidToken) as e:
        issuer().decode(forged)
    assert e.value.reason == "bad_algorithm"


def test_algorithm_confusion_rejected():
    key, _ = es256()
    # Attacker signs HS256 using the (public) PEM as the HMAC secret.
    forged = jwt.encode({"sub": "admin"}, "x" * 32, algorithm="HS256", headers={"kid": "e1"})
    with pytest.raises(InvalidToken) as e:
        issuer(Keyring(key)).decode(forged)
    assert e.value.reason == "bad_algorithm"


def test_bad_signature_and_malformed():
    t = issuer(Keyring(SigningKey.hmac("x" * 32))).issue_access("u1")
    with pytest.raises(InvalidToken) as e:
        issuer().decode(t.token)
    assert e.value.reason == "bad_signature"
    for bad in ["", "abc", "a.b.c", None]:
        with pytest.raises(InvalidToken) as e:
            issuer().decode(bad)
        assert e.value.reason == "malformed"


def test_refresh_never_accepted_as_access_and_family():
    ti = issuer()
    r = ti.issue_refresh("u1")
    assert r.family
    with pytest.raises(InvalidToken) as e:
        ti.decode(r.token)
    assert e.value.reason == "wrong_type"
    c = ti.decode(r.token, REFRESH)
    assert c["fid"] == r.family and c["jti"] == r.jti
    r2 = ti.issue_refresh("u1", family=c["fid"])
    assert r2.family == r.family and r2.jti != r.jti
    with pytest.raises(InvalidToken):
        ti.decode(ti.issue_access("u1").token, REFRESH)


def test_refresh_without_family_rejected():
    tok = jwt.encode(
        {
            "iss": "arpa-test",
            "aud": "arpa-api",
            "sub": "u",
            "iat": T0,
            "nbf": T0,
            "exp": T0 + timedelta(hours=1),
            "jti": "j",
            "typ": REFRESH,
        },
        SECRET,
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(InvalidToken) as e:
        issuer(clock=Clock()).decode(tok, REFRESH)
    assert e.value.reason == "missing_claim"


def test_expiry_and_leeway_with_injected_clock():
    clock = Clock()
    ti = issuer(clock=clock)
    t = ti.issue_access("u1")
    clock.t = T0 + timedelta(minutes=15, seconds=30)
    assert ti.decode(t.token)["sub"] == "u1"  # within the 60 s leeway
    clock.t = T0 + timedelta(minutes=17)
    with pytest.raises(InvalidToken) as e:
        ti.decode(t.token)
    assert e.value.reason == "expired"
    clock.t = T0 - timedelta(minutes=5)
    with pytest.raises(InvalidToken) as e:
        ti.decode(t.token)
    assert e.value.reason == "not_yet_valid"


def test_expiry_real_clock():
    ti = issuer(leeway=timedelta(0))
    t = ti.issue_access("u1", ttl=timedelta(seconds=-1))
    with pytest.raises(InvalidToken) as e:
        ti.decode(t.token)
    assert e.value.reason == "expired"


def test_audience_issuer_and_required_claims():
    t = issuer().issue_access("u1")
    with pytest.raises(InvalidToken) as e:
        issuer(audience="other").decode(t.token)
    assert e.value.reason == "wrong_audience"
    with pytest.raises(InvalidToken) as e:
        issuer(issuer="other").decode(t.token)
    assert e.value.reason == "wrong_issuer"
    multi = issuer(audience=["arpa-api", "arpa-web"])
    assert multi.decode(multi.issue_access("u").token)["aud"] == ["arpa-api", "arpa-web"]
    bare = jwt.encode({"sub": "u"}, SECRET, algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(InvalidToken) as e:
        issuer().decode(bare)
    assert e.value.reason == "missing_claim"


def test_configuration_errors():
    with pytest.raises(ValueError, match="shorter"):
        SigningKey.hmac("short")
    with pytest.raises(ValueError, match="unsupported"):
        SigningKey("k", "none", signing=SECRET)
    with pytest.raises(ValueError, match="kid"):
        SigningKey("", "HS256", signing=SECRET)
    with pytest.raises(ValueError, match="secret"):
        SigningKey("k", "HS256")
    with pytest.raises(ValueError, match="public"):
        SigningKey("k", "ES256", signing=b"pem")
    with pytest.raises(ValueError, match="unique"):
        Keyring(SigningKey.hmac(SECRET), (SigningKey.hmac(SECRET),))
    with pytest.raises(ValueError, match="issuer"):
        TokenIssuer(Keyring(SigningKey.hmac(SECRET)), issuer="", audience="a")
    with pytest.raises(ValueError, match="audience"):
        TokenIssuer(Keyring(SigningKey.hmac(SECRET)), issuer="i", audience=[])
    with pytest.raises(ValueError, match="reserved"):
        issuer().issue_access("u", {"sub": "admin"})
    with pytest.raises(ValueError, match="subject"):
        issuer().issue_access("")
    assert SECRET not in repr(SigningKey.hmac(SECRET))
