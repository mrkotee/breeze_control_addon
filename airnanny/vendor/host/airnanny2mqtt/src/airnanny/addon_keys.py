"""Operator-supplied context keys, for deployments without DPAPI.

On the commissioning machine each network key is wrapped by Windows DPAPI and
can be unwrapped only under the account that commissioned the units. Home
Assistant OS on a Raspberry Pi has no equivalent, so there the operator
supplies each key through the add-on's configuration and it is held in memory
for the life of the process. The key then exists in one place rather than two,
and nothing in this module writes one to disk or returns it in a message.

A supplied key is checked against a digest of exactly the bytes DPAPI wraps --
the context's 32-character secret reference followed by the 16 key bytes --
so a transcription error is caught before the radio transmits anything, and
the digest that makes the check possible reveals nothing about the key.
"""
import hashlib
import hmac
import os
import re

KEY_BYTES = 16
REF_PATTERN = re.compile(r'\A[0-9a-f]{32}\Z')
KEY_PATTERN = re.compile(r'\A[0-9a-fA-F]{32}\Z')
DIGEST_PATTERN = re.compile(r'\A[0-9a-f]{64}\Z')


class KeyOptionError(Exception):
    """A supplied key is missing, malformed, or not the one the store expects.

    Raised instead of falling back to any other source: a context whose key
    cannot be established must not transmit, because a frame built with the
    wrong key still spends a counter that can never be reused.
    """


def key_digest(ref, key):
    """Digest of the plaintext DPAPI protects for `ref`.

    Keeping the same preimage as the protected form means the digest can be
    produced on the commissioning machine from the wrapped secret alone,
    without a separate record that could drift away from it.
    """
    if not REF_PATTERN.match(ref):
        raise KeyOptionError('malformed secret reference')
    if len(key) != KEY_BYTES:
        raise KeyOptionError('key length')
    return hashlib.sha256(ref.encode('ascii') + key).hexdigest()


def parse_key(text):
    """Accept the 32 hex characters an operator types, and nothing else."""
    text = (text or '').strip()
    if not KEY_PATTERN.match(text):
        raise KeyOptionError('network key must be 32 hex characters')
    return bytes.fromhex(text)


def option_names(slot):
    if slot not in (0, 1):
        raise KeyOptionError('no such context: %r' % (slot,))
    return 'AIRNANNY_CTX%d_KEY' % slot, 'AIRNANNY_CTX%d_KEY_SHA256' % slot


def configured(environ=None):
    """Is this deployment supplying keys itself?

    False leaves the existing DPAPI path untouched, so a Windows run that sets
    nothing behaves exactly as it did before this module existed.
    """
    environ = os.environ if environ is None else environ
    return any(environ.get(option_names(slot)[0]) for slot in (0, 1))


def resolve_key(slot, ref, environ=None):
    """The key for `slot`, verified against the digest for `ref`.

    Both halves are required. A key without its digest cannot be checked, and
    an unchecked key is the thing this is here to prevent.
    """
    environ = os.environ if environ is None else environ
    key_name, digest_name = option_names(slot)
    raw, expected = environ.get(key_name), (environ.get(digest_name) or '').strip().lower()
    if not raw:
        raise KeyOptionError('%s is not set' % key_name)
    if not DIGEST_PATTERN.match(expected):
        raise KeyOptionError('%s is missing or malformed' % digest_name)
    key = parse_key(raw)
    if not hmac.compare_digest(key_digest(ref, key), expected):
        raise KeyOptionError('ctx%d key does not match its digest' % slot)
    return key
