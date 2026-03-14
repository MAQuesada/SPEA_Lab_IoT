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
from spea_lab_iot.config import (
    SALT_AUTH,
    SALT_SESS
)

# ---------------------------------------------------------------------------
# DH classic (RFC 3526 – 2048-bit MODP group 14)
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
        salt=SALT_AUTH,
        info=b"auth-key-v1",
    ).derive(pin.encode())


def _hkdf_session(raw_shared: bytes) -> bytes:
    """Derive a 32-byte session key from raw DH shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT_SESS,
        info=b"session-key-v1",
    ).derive(raw_shared)


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------


class KeyAgreement(ABC):
    """Abstract key agreement.  Instantiate via KeyAgreement.create()."""

    def __init__(self, pin: str) -> None:
        self._auth_key = _derive_auth_key(pin)

    # Factory -------------------------------------------------------------

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

    # Abstract interface --------------------------------------------------

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """Return our ephemeral public key as raw bytes (to send over MQTT)."""

    @abstractmethod
    def derive_session_key(self, peer_public_key_bytes: bytes) -> bytes:
        """Compute the 32-byte shared session key from peer's public key bytes."""

    # Transcript HMAC (shared implementation) ----------------------------

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


# -----------------------DH classic implementation------------------------
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


# -----------------ECDH ephemeral (X25519)-------------------------------
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
# ---------------------------------------------------------------------------
# Key Rotation Manager (R4) - Automatic DH-based rotation
# ---------------------------------------------------------------------------

import time
from threading import Timer, Lock


class KeyRotationManager:
    
    
    def __init__(self, rotation_interval_seconds=300):
        """
        Initialize rotation manager.
        
        Args:
            rotation_interval_seconds: Time between rotations (default: 300 = 5 min)
        """
        self.rotation_interval = rotation_interval_seconds
        self.last_rotation_time = time.time()
        self.rotation_timer = None
        self.rotation_callback = None
        self.lock = Lock()
        self.is_running = False
        
        print(f"[KeyRotation] Manager created (interval: {rotation_interval_seconds}s)")
    
    def should_rotate(self):
        """
        Check if rotation is needed based on time elapsed.
        
        Returns:
            bool: True if rotation interval has passed
        """
        with self.lock:
            elapsed = time.time() - self.last_rotation_time
            return elapsed >= self.rotation_interval
    
    def mark_rotated(self):
        """Mark that a rotation just occurred."""
        with self.lock:
            self.last_rotation_time = time.time()
            print(f"[KeyRotation] Rotation completed at {time.strftime('%H:%M:%S')}")
    
    def start_automatic_rotation(self, on_rotate_callback):
        """
        Start automatic rotation timer.
        
        Args:
            on_rotate_callback: Function to call when rotation is needed.
                               This should perform a new DH handshake.
                               Signature: callback() -> None
        """
        if self.is_running:
            print("[KeyRotation] ⚠️  Rotation already running")
            return
        
        self.rotation_callback = on_rotate_callback
        self.is_running = True
        self._schedule_next_rotation()
        print(f"[KeyRotation] ✅ Automatic rotation started (every {self.rotation_interval}s)")
    
    def stop_automatic_rotation(self):
        """Stop automatic rotation."""
        with self.lock:
            if self.rotation_timer:
                self.rotation_timer.cancel()
                self.rotation_timer = None
            self.is_running = False
        print("[KeyRotation] ⏸️  Automatic rotation stopped")
    
    def _schedule_next_rotation(self):
        """Schedule the next rotation using a timer."""
        def rotate():
            if not self.is_running:
                return
            
            print(f"\n🔄 [KeyRotation] Triggering rotation after {self.rotation_interval}s")
            
            if self.rotation_callback:
                try:
                    # Call the callback to perform DH handshake
                    self.rotation_callback()
                    self.mark_rotated()
                except Exception as e:
                    print(f"❌ [KeyRotation] Error during rotation: {e}")
            
            # Schedule next rotation
            if self.is_running:
                self._schedule_next_rotation()
        
        with self.lock:
            self.rotation_timer = Timer(self.rotation_interval, rotate)
            self.rotation_timer.daemon = True  # Won't block program exit
            self.rotation_timer.start()
    
    def get_time_until_rotation(self):
        """
        Get remaining time until next rotation.
        
        Returns:
            float: Seconds remaining
        """
        with self.lock:
            elapsed = time.time() - self.last_rotation_time
            return max(0, self.rotation_interval - elapsed)
    
    def get_rotation_stats(self):
        """
        Get rotation statistics.
        
        Returns:
            dict: Statistics including interval, last rotation time, etc.
        """
        with self.lock:
            elapsed = time.time() - self.last_rotation_time
            return {
                'interval_seconds': self.rotation_interval,
                'last_rotation': time.strftime('%Y-%m-%d %H:%M:%S', 
                                              time.localtime(self.last_rotation_time)),
                'elapsed_seconds': round(elapsed, 2),
                'remaining_seconds': round(max(0, self.rotation_interval - elapsed), 2),
                'is_running': self.is_running
            }


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Testing KeyRotation with DH handshake...\n")
    
    pin = "1234"
    rotation_count = [0]
    
    def perform_dh_rotation():
        """
        This callback performs a complete DH handshake for rotation.
        In real usage, this would exchange keys via MQTT.
        """
        rotation_count[0] += 1
        print(f"🔄 ROTATION #{rotation_count[0]}")
        
        # Perform new DH handshake (both sides)
        sensor_ka = KeyAgreement.create("ecdh_ephemeral", pin)
        platform_ka = KeyAgreement.create("ecdh_ephemeral", pin)
        
        sensor_pub = sensor_ka.public_key_bytes()
        platform_pub = platform_ka.public_key_bytes()
        
        # Both derive new session key
        sensor_session = sensor_ka.derive_session_key(platform_pub)
        platform_session = platform_ka.derive_session_key(sensor_pub)
        
        assert sensor_session == platform_session
        print(f"   ✅ New session key: {sensor_session.hex()[:32]}...")
    
    # Create rotation manager (rotate every 5 seconds for testing)
    rotation_mgr = KeyRotationManager(rotation_interval_seconds=5)
    
    # Start automatic rotation
    rotation_mgr.start_automatic_rotation(perform_dh_rotation)
    
    print("⏱️  Rotation configured: every 5 seconds")
    print("⏱️  Test will run for 20 seconds (4 rotations expected)")
    print("⏱️  Press Ctrl+C to stop\n")
    
    try:
        time.sleep(20)
        
        print(f"\n{'='*60}")
        print(f"TEST COMPLETE")
        print(f"{'='*60}")
        print(f"✅ Rotations performed: {rotation_count[0]}")
        print(f"✅ Expected: 4")
        
        if rotation_count[0] == 4:
            print("\n🎉 TEST PASSED! Rotation with DH works!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted")
    finally:
        rotation_mgr.stop_automatic_rotation()