import json
import os
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.exceptions import InvalidTag
from .binary import CodecError, Reader, uint


class AuthenticationError(CodecError):
    pass


class KeyStore:
    """Per-context key ownership. Never include material in repr or errors."""
    def __init__(self):
        self.__keys = {}

    def __repr__(self):
        return "KeyStore(<redacted>)"

    def put(self, sequence: int, key: bytes):
        uint(sequence, 1)
        if len(key) != 16:
            raise CodecError("NWK key must be 128 bits")
        self.__keys[sequence] = bytes(key)

    def get(self, sequence: int) -> bytes:
        try:
            return self.__keys[sequence]
        except KeyError:
            raise CodecError("unknown NWK key sequence") from None

    def load(self, context: str, sequence: int = 0, local_file: Path | None = None):
        name = f"AIRNANNY_{context.upper()}_NWK_KEY"
        value = os.environ.get(name)
        if value is None and local_file is not None:
            # Caller must supply an ignored local secrets file, never a fixture.
            value = json.loads(local_file.read_text(encoding="utf-8")).get(name)
        if value is None:
            raise CodecError("NWK key unavailable")
        try:
            key = bytes.fromhex(value)
        except (ValueError, TypeError):
            raise CodecError("invalid key encoding") from None
        self.put(sequence, key)


@dataclass(frozen=True)
class SecurityHeader:
    control: int
    counter: int
    source_ieee: int
    key_sequence: int

    def serialize(self, *, effective: bool = False) -> bytes:
        if self.control not in (0x28, 0x2d):
            raise CodecError("unsupported security control")
        return (uint(0x2d if effective else self.control, 1) + uint(self.counter, 4)
                + uint(self.source_ieee, 8) + uint(self.key_sequence, 1))

    @classmethod
    def parse(cls, data: bytes):
        r = Reader(data)
        result = cls(r.uint(1), r.uint(4), r.uint(8), r.uint(1))
        result.serialize()
        return result, r.rest()

    @property
    def nonce(self) -> bytes:
        self.serialize()
        return uint(self.source_ieee, 8) + uint(self.counter, 4) + b"\x2d"


def encrypt(nwk, header: SecurityHeader, plaintext: bytes, keys: KeyStore) -> bytes:
    aad = nwk.header + header.serialize(effective=True)
    return header.serialize() + AESCCM(keys.get(header.key_sequence), tag_length=4).encrypt(header.nonce, plaintext, aad)


def decrypt(nwk, keys: KeyStore):
    header, encrypted = SecurityHeader.parse(nwk.payload)
    if len(encrypted) < 4:
        raise CodecError("missing MIC32")
    aad = nwk.header + header.serialize(effective=True)
    try:
        plaintext = AESCCM(keys.get(header.key_sequence), tag_length=4).decrypt(header.nonce, encrypted, aad)
    except InvalidTag:
        raise AuthenticationError("NWK MIC verification failed") from None
    return header, plaintext
