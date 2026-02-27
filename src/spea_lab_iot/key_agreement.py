"""
Key agreement module for SPEA Lab IoT.

Supports two algorithms:
  - auth_dh       : Diffie-Hellman (RFC 3526, 2048-bit MODP group)
  - ecdh_ephemeral: Elliptic Curve DH with X25519 ephemeral keys

Authentication: HMAC-SHA256 over the handshake transcript, keyed with a
pre-shared secret derived from the device PIN.  This prevents a MitM attack
even when the MQTT broker is untrusted.

Public interface consumed by device.py and platform.py:
  - KeyAgreement.create(algorithm, pin)  -> KeyAgreement instance
  - ka.public_key_bytes()                -> bytes  (send this to the peer)
  - ka.derive_session_key(peer_pub)      -> bytes  (32-byte session key)
  - ka.make_transcript_hmac(parts)       -> str    (hex, sign transcript)
  - ka.verify_transcript_hmac(parts, h)  -> bool

R2-R3 integration note:
  derive_session_key() returns 32 raw bytes.  R2-R3 should use these bytes
  directly as the session key (or run them through their own KDF if needed).
  The auth_key used for HMAC is derived here from the PIN via HKDF-SHA256.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# DH classic (RFC 3526 – 2048-bit MODP group 14)
# ---------------------------------------------------------------------------
_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_G = 2
_DH_KEY_BITS = 2048


def _derive_auth_key(pin: str) -> bytes:
    """Derive a 32-byte auth key from PIN using HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"spea-lab-iot-auth",
        info=b"auth-key-v1",
    ).derive(pin.encode())


def _hkdf_session(raw_shared: bytes) -> bytes:
    """Derive a 32-byte session key from raw DH shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"spea-lab-iot-session",
        info=b"session-key-v1",
    ).derive(raw_shared)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class KeyAgreement(ABC):
    """Abstract key agreement.  Instantiate via KeyAgreement.create()."""

    def __init__(self, pin: str) -> None:
        self._auth_key = _derive_auth_key(pin)

    # -- factory -------------------------------------------------------------

    @staticmethod
    def create(algorithm: str, pin: str) -> "KeyAgreement":
        """
        Factory method.

        algorithm: "auth_dh" | "ecdh_ephemeral"
        pin      : shared secret (platform PIN for the device)
        """
        if algorithm == "auth_dh":
            return _DHKeyAgreement(pin)
        elif algorithm == "ecdh_ephemeral":
            return _ECDHKeyAgreement(pin)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm!r}")

    # -- abstract interface --------------------------------------------------

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """Return our ephemeral public key as raw bytes (to send over MQTT)."""

    @abstractmethod
    def derive_session_key(self, peer_public_key_bytes: bytes) -> bytes:
        """Compute the 32-byte shared session key from peer's public key bytes."""

    # -- transcript HMAC (shared implementation) ----------------------------

    def make_transcript_hmac(self, parts: list[bytes]) -> str:
        """
        Sign the handshake transcript with the auth key.

        parts: ordered list of byte strings that both sides agree on
               e.g. [device_id, our_pub, peer_pub]
        Returns hex string.
        """
        transcript = b"|".join(parts)
        return hmac.new(self._auth_key, transcript, hashlib.sha256).hexdigest()

    def auth_key_bytes(self) -> bytes:
        """
        Return the 32-byte auth key derived from PIN.
        R5 uses this as the MAC key for AES-CBC-HMAC (AE mode).
        """
        return self._auth_key

    def verify_transcript_hmac(self, parts: list[bytes], received_hex: str) -> bool:
        """Verify a transcript HMAC received from the peer."""
        expected = self.make_transcript_hmac(parts)
        return hmac.compare_digest(expected, received_hex)


# ---------------------------------------------------------------------------
# DH classic implementation
# ---------------------------------------------------------------------------


class _DHKeyAgreement(KeyAgreement):
    """Classic Diffie-Hellman using RFC 3526 2048-bit MODP group."""

    def __init__(self, pin: str) -> None:
        super().__init__(pin)
        # Generate ephemeral private key
        self._private = int.from_bytes(os.urandom(_DH_KEY_BITS // 8), "big")
        self._private = self._private % (_DH_P - 2) + 2  # ensure 2 <= x <= P-2
        self._public = pow(_DH_G, self._private, _DH_P)

    def public_key_bytes(self) -> bytes:
        return self._public.to_bytes(_DH_KEY_BITS // 8, "big")

    def derive_session_key(self, peer_public_key_bytes: bytes) -> bytes:
        peer_pub = int.from_bytes(peer_public_key_bytes, "big")
        if not (2 <= peer_pub <= _DH_P - 2):
            raise ValueError("Invalid peer DH public key")
        shared = pow(peer_pub, self._private, _DH_P)
        raw = shared.to_bytes(_DH_KEY_BITS // 8, "big")
        return _hkdf_session(raw)


# ---------------------------------------------------------------------------
# ECDH ephemeral (X25519)
# ---------------------------------------------------------------------------


class _ECDHKeyAgreement(KeyAgreement):
    """Ephemeral ECDH using X25519 (32-byte keys, fast, modern)."""

    def __init__(self, pin: str) -> None:
        super().__init__(pin)
        self._private_key = X25519PrivateKey.generate()

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def derive_session_key(self, peer_public_key_bytes: bytes) -> bytes:
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        raw_shared = self._private_key.exchange(peer_pub)
        return _hkdf_session(raw_shared)
