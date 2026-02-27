import json
import os
import time
from pathlib import Path
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from spea_lab_iot.config import SALT_KM


class KeyManager:
    """
    Manages authentication and session keys for IoT devices/platform.
    Handles key derivation from PIN, session key rotation, and secure storage (simulated).
    """

    def __init__(self, device_id: str, storage_dir: str = ".keys"):
        self.device_id = device_id
        self.storage_dir = Path(storage_dir)
        self.storage_file = self.storage_dir / f"{device_id}.keys"

        # Keys
        self.master_key = None  # Derived from PIN (Authentication Key)
        self.session_key = None  # Used for encryption (Rotated)
        self.session_key_id = 0

        # Rotation state
        self.last_rotation_ts = 0.0
        self.msg_count = 0

        # Configuration
        self.rotation_interval_sec = int(
            os.environ.get("KEY_ROTATION_INTERVAL_SEC", "60")
        )
        self.rotation_msg_limit = int(os.environ.get("KEY_ROTATION_MSG_LIMIT", "100"))

        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def derive_master_key(self, pin: str, salt: bytes = SALT_KM) -> bytes:
        """Derives a master key (authentication key) from the PIN."""
        # Using the same parameters as the original code
        key = PBKDF2(
            password=pin,
            salt=salt,
            dkLen=32,  # 256-bit key
            count=100_000,
            hmac_hash_module=SHA256,
        )
        self.master_key = key
        return key

    def set_session_key(self, key: bytes, key_id: int):
        """Sets the current session key and resets rotation counters."""
        self.session_key = key
        self.session_key_id = key_id
        self.last_rotation_ts = time.time()
        self.msg_count = 0
        self.save_keys()

    def get_session_key(self) -> tuple[bytes, int]:
        """Returns the current session key and its ID."""
        if not self.session_key:
            raise ValueError("Session key not established.")
        self.msg_count += 1
        return self.session_key, self.session_key_id

    def check_rotation_needed(self) -> bool:
        """Checks if session key rotation is needed based on time or message count."""
        if not self.session_key:
            return True  # If no session key, we need one (simulated rotation/exchange)

        time_elapsed = time.time() - self.last_rotation_ts
        if time_elapsed > self.rotation_interval_sec:
            return True

        if self.msg_count >= self.rotation_msg_limit:
            return True

        return False

    def save_keys(self):
        """Simulates secure storage by saving keys to a file (should be encrypted in real usage)."""
        data = {
            "master_key": self.master_key.hex() if self.master_key else None,
            "session_key": self.session_key.hex() if self.session_key else None,
            "session_key_id": self.session_key_id,
            "last_rotation_ts": self.last_rotation_ts,
            "msg_count": self.msg_count,
        }
        with open(self.storage_file, "w") as f:
            json.dump(data, f)

    def load_keys(self) -> bool:
        """Loads keys from storage. Returns True if successful."""
        if not self.storage_file.exists():
            return False
        try:
            with open(self.storage_file, "r") as f:
                data = json.load(f)

            if data.get("master_key"):
                self.master_key = bytes.fromhex(data["master_key"])
            if data.get("session_key"):
                self.session_key = bytes.fromhex(data["session_key"])
            self.session_key_id = data.get("session_key_id", 0)
            self.last_rotation_ts = data.get("last_rotation_ts", 0.0)
            self.msg_count = data.get("msg_count", 0)
            return True
        except Exception as e:
            print(f"Error loading keys: {e}")
            return False

    def get_typed_keys(self) -> tuple[bytes, bytes]:
        """Returns (enc_key, auth_key) from the current session key.
        For AES-GCM (using 128-bit), we might use just the first 16 bytes or specific derivation.
        For AES-CBC+HMAC, we split the 32-byte key into 16+16.
        """
        if not self.session_key:
            raise ValueError("Session key not established.")

        # Consistent splitting/usage:
        # enc_key = first 16 bytes
        # auth_key = last 16 bytes
        # Even for GCM, we can just use the first 16 bytes (AES-128) or the full 32 bytes (AES-256).
        # The existing code used key[:16] for 'session_key' (encryption) and key[16:] for 'auth_key'.

        enc_key = self.session_key[:16]
        auth_key = self.session_key[16:]
        return enc_key, auth_key

    def generate_random_session_key(self) -> bytes:
        """Generates a random 32-byte session key (for the Platform side to generate)."""
        return get_random_bytes(32)
