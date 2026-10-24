"""SPEC-0007 SEC-49 / SEC-53: keyed audit content digests and their versioned key ring."""

import base64
import hashlib
import secrets

import pytest
from django.test import override_settings

from apps.audit.digests import MISMATCH, UNVERIFIABLE, VALID, content_digest, verify_digest
from apps.core.logging import SENSITIVE_KEY, redact
from tests.test_settings import _load_prod_settings, _prod_env, _run

CONTEXT = "trilha.findings.content-digest"


def key():
    return secrets.token_bytes(32)


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_content_digest_depends_on_key_and_context():
    k1, k2 = key(), key()
    with override_settings(AUDIT_DIGEST_KEYS={"k1": k1}, AUDIT_DIGEST_ACTIVE_KEY_ID="k1"):
        digest = content_digest("hunter2", context=CONTEXT)
        other_context = content_digest("hunter2", context="trilha.other")
    algorithm, key_id, value = digest.split(":")
    assert (algorithm, key_id, len(value)) == ("hmac-sha256", "k1", 64)
    assert value != hashlib.sha256(b"hunter2").hexdigest()  # never a plain hash (CWE-759)
    assert other_context != digest
    with override_settings(AUDIT_DIGEST_KEYS={"k1": k2}, AUDIT_DIGEST_ACTIVE_KEY_ID="k1"):
        assert content_digest("hunter2", context=CONTEXT) != digest  # reproducible only with k1
        assert verify_digest("hunter2", digest, context=CONTEXT) == (MISMATCH, "k1")
    with override_settings(AUDIT_DIGEST_KEYS={}, AUDIT_DIGEST_ACTIVE_KEY_ID=""):
        with pytest.raises(Exception, match="No audit digest key"):
            content_digest("x", context=CONTEXT)


def test_digest_key_ring_rotation_keeps_history_verifiable_cwe_324():
    k1, k2 = key(), key()
    with override_settings(AUDIT_DIGEST_KEYS={"k1": k1}, AUDIT_DIGEST_ACTIVE_KEY_ID="k1"):
        old = content_digest("first", context=CONTEXT)
    # Rotation: a new key signs; the old one stays in the ring only to verify.
    with override_settings(AUDIT_DIGEST_KEYS={"k1": k1, "k2": k2}, AUDIT_DIGEST_ACTIVE_KEY_ID="k2"):
        new = content_digest("second", context=CONTEXT)
        assert new.startswith("hmac-sha256:k2:")
        assert verify_digest("first", old, context=CONTEXT) == (VALID, "k1")
        assert verify_digest("second", new, context=CONTEXT) == (VALID, "k2")
        assert verify_digest("changed", new, context=CONTEXT) == (MISMATCH, "k2")
    # A deliberately retired key makes its digests unverifiable: never valid, never mismatch.
    with override_settings(AUDIT_DIGEST_KEYS={"k2": k2}, AUDIT_DIGEST_ACTIVE_KEY_ID="k2"):
        assert verify_digest("first", old, context=CONTEXT) == (UNVERIFIABLE, "k1")
        assert verify_digest("anything", old, context=CONTEXT) == (UNVERIFIABLE, "k1")
        for malformed in ("", "sha256:abc", f"hmac-sha256:K2:{'0' * 64}", None, 5):
            assert verify_digest("second", malformed, context=CONTEXT)[0] == MISMATCH

    # Production refuses an incomplete or weak ring, naming the variable but never the key.
    strong = encoded(key())
    for keys, active in (
        (f"k1:{encoded(secrets.token_bytes(31))}", "k1"),  # shorter than 32 bytes
        (f"k1:{strong},k1:{encoded(key())}", "k1"),  # duplicate IDs
        (f"k1:{strong}", "k2"),  # active ID not in the ring
        (f"k1:{strong}", ""),
        ("k1:change-me-digest-key", "k1"),  # the .env.example placeholder
        (f"K1:{strong}", "K1"),  # IDs are lowercase
        (f"k1:{strong}!", "k1"),  # not base64url
        (strong, "k1"),  # no ID
    ):
        env = _prod_env(AUDIT_DIGEST_KEYS=keys, AUDIT_DIGEST_ACTIVE_KEY_ID=active)
        result = _run(["-c", "import config.settings.prod"], env)
        assert result.returncode != 0, keys
        assert "AUDIT_DIGEST" in result.stderr
        assert strong not in result.stderr
    loaded = _load_prod_settings(
        _prod_env(
            AUDIT_DIGEST_KEYS=f"k1:{strong}, k2:{encoded(key())}", AUDIT_DIGEST_ACTIVE_KEY_ID="k2"
        ),
        "AUDIT_DIGEST_ACTIVE_KEY_ID",
    )
    assert loaded == {"AUDIT_DIGEST_ACTIVE_KEY_ID": "k2"}
    # Services without a ring (migrate, worker) load; the HTTP application refuses to start.
    assert _run(["-c", "import config.settings.prod"], _prod_env()).returncode == 0
    refused = _run(["-c", "import config.wsgi"], _prod_env())
    assert refused.returncode != 0 and "AUDIT_DIGEST_KEYS" in refused.stderr
    serving = _prod_env(AUDIT_DIGEST_KEYS=f"k1:{strong}", AUDIT_DIGEST_ACTIVE_KEY_ID="k1")
    assert _run(["-c", "import config.wsgi"], serving).returncode == 0


def test_audit_digest_keys_are_not_redacted():
    # The digests must stay readable in audit metadata; the central redaction would blank them.
    names = ("body_digest", "description_digest", "reason_digest", "body_length")
    assert not [name for name in names if SENSITIVE_KEY.search(name)]
    payload = {name: "hmac-sha256:k1:" + "0" * 64 for name in names}
    assert redact(payload) == payload
