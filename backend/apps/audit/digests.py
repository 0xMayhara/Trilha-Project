"""Keyed digests of user content kept out of audit events (SPEC-0007 SEC-49, SEC-53; ADR-0008 §2).

A digest proves, to whoever holds the key, that stored text matches what an audit event recorded,
without the event holding the text. HMAC-SHA256 keeps audit readers from confirming guessed content
(a plain hash of a short secret is a dictionary lookup). Every digest names its key, so rotation
adds a key without breaking older digests, and a digest whose key is gone is unverifiable, never a
false match or mismatch."""

import hashlib
import hmac
import re

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

VALID, MISMATCH, UNVERIFIABLE = "valid", "mismatch", "unverifiable"
_DIGEST = re.compile(r"hmac-sha256:([a-z0-9]{1,16}):([0-9a-f]{64})")


def _mac(key, context, text):
    # The context separates uses of one key; NUL cannot occur in a context constant.
    message = context.encode() + b"\x00" + text.encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def content_digest(text, *, context):
    """`hmac-sha256:<key id>:<hex>` of the UTF-8 text under the active key."""
    key_id = settings.AUDIT_DIGEST_ACTIVE_KEY_ID
    key = settings.AUDIT_DIGEST_KEYS.get(key_id)
    if key is None:
        # Fail closed: the change and its audit event roll back together.
        raise ImproperlyConfigured("No audit digest key is configured.")
    return f"hmac-sha256:{key_id}:{_mac(key, context, text)}"


def verify_digest(text, digest, *, context):
    """(outcome, key id). A malformed digest cannot have been written here: it is a mismatch."""
    match = _DIGEST.fullmatch(digest) if isinstance(digest, str) else None
    if match is None:
        return MISMATCH, None
    key_id, expected = match.groups()
    key = settings.AUDIT_DIGEST_KEYS.get(key_id)
    if key is None:
        return UNVERIFIABLE, key_id
    if hmac.compare_digest(_mac(key, context, text), expected):
        return VALID, key_id
    return MISMATCH, key_id
