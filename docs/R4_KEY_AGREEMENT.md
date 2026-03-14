# R4: Key Agreement with Automatic Rotation

To ensure that session keys used for data encryption are established securely, a key agreement protocol has been implemented between devices and the platform. This prevents any third party from learning the session key, even if they observe MQTT traffic during the handshake. After a device is enrolled, it initiates a Diffie-Hellman handshake with the platform. Once the handshake is complete, both sides independently derive the same `session_key` without ever transmitting it over the network.

Additionally, automatic key rotation has been implemented. Instead of transmitting new keys, the system performs a complete DH handshake periodically to generate new session keys, limiting the impact of key compromise.

---

## Library

The `cryptography` library has been used to implement the key agreement mechanisms, providing robust implementations of Diffie-Hellman and ECDH algorithms.

---

## Supported Algorithms

The system supports two key agreement algorithms:

* **Classic Diffie-Hellman (auth_dh).** Uses RFC 3526 2048-bit MODP group 14 with generator 2. This algorithm is slower (~30 seconds for parameter generation) but provides wide compatibility. The shared secret is derived through modular exponentiation, and HKDF-SHA256 is applied to produce the final `session_key`.

* **Elliptic Curve Diffie-Hellman (ecdh_ephemeral).** Uses the modern X25519 elliptic curve for key agreement. This algorithm generates 256-bit ephemeral keys and is significantly faster (<1 second) than classic DH while providing equivalent security. The shared secret is derived through elliptic curve point multiplication, followed by HKDF-SHA256 to produce the `session_key`.

Both algorithms include HMAC-SHA256 authentication of the handshake transcript to prevent Man-in-the-Middle attacks, even when the MQTT broker is untrusted.

#### Summary
| Algorithm | Type | Key Size | Speed | Recommended |
|-----------|------|----------|-------|-------------|
| `auth_dh` | Classic DH (RFC 3526) | 2048 bits | Slow (~30s) | Legacy only |
| `ecdh_ephemeral` | ECDH X25519 | 256 bits | Fast (<1s) | ✅ Yes |

---

## Key Derivation Process

### Authentication Key Derivation

The authentication key is derived from the device PIN using HKDF-SHA256:
```
PIN → HKDF-SHA256 → auth_key (32 bytes)

Salt: b"spea-lab-iot-auth"
Info: b"auth-key-v1"
```

This key is used to create and verify HMAC signatures during the handshake.

### Session Key Derivation

After the DH or ECDH shared secret is computed, HKDF-SHA256 is applied to derive the session key:
```
shared_secret → HKDF-SHA256 → session_key (32 bytes)

Salt: b"spea-lab-iot-session"
Info: b"session-key-v1"
```

This ensures the session key has high entropy and is suitable for cryptographic operations.

---

## Handshake Protocol: Step by Step

### Step 1: Initialization

Both device and platform create `KeyAgreement` instances with the same PIN:
```python
ka = KeyAgreement.create("ecdh_ephemeral", pin="1234")
```

### Step 2: Generate Ephemeral Keys

Each side generates an ephemeral key pair:
```python
our_public_key = ka.public_key_bytes()
```

For ECDH, this generates a random X25519 private key and computes the corresponding public key. For classic DH, this generates a random exponent and computes g^x mod p.

### Step 3: Exchange Public Keys

Public keys are exchanged via MQTT (encoded in hexadecimal format). The device sends its public key to the platform, and the platform responds with its public key.

### Step 4: Compute Shared Secret

Both sides independently compute the same shared secret:
```python
session_key = ka.derive_session_key(peer_public_key)
```

The shared secret is never transmitted. It is computed locally using:
- **ECDH:** Scalar multiplication of peer's public point with own private scalar
- **Classic DH:** Modular exponentiation: (peer_public)^private mod p

### Step 5: Authenticate the Exchange

To prevent Man-in-the-Middle attacks, both sides create and verify HMAC signatures:
```python
transcript = [device_id, our_public, peer_public]
our_hmac = ka.make_transcript_hmac(transcript)

# Verify peer's HMAC
is_valid = ka.verify_transcript_hmac(transcript, peer_hmac)
```

The transcript includes device ID and both public keys to ensure freshness and binding to this specific handshake.

---

## Automatic Key Rotation

### Purpose

Key rotation periodically renews the session key to limit the exposure window if a key is compromised. Instead of transmitting a new key, the system performs a complete DH handshake to generate a fresh session key.

### Implementation

The `KeyRotationManager` class manages automatic rotation:
```python
from spea_lab_iot.key_agreement import KeyRotationManager

# Create rotation manager with 5-minute interval
rotation_mgr = KeyRotationManager(rotation_interval_seconds=300)

# Define what happens during rotation
def perform_rotation():
    # Generate new KeyAgreement instances
    new_ka_device = KeyAgreement.create("ecdh_ephemeral", pin)
    new_ka_platform = KeyAgreement.create("ecdh_ephemeral", pin)
    
    # Exchange new public keys via MQTT
    new_device_pub = new_ka_device.public_key_bytes()
    new_platform_pub = new_ka_platform.public_key_bytes()
    
    # Both compute new session key
    new_session_key = new_ka_device.derive_session_key(new_platform_pub)
    
    # Update session key in the system

# Start automatic rotation
rotation_mgr.start_automatic_rotation(perform_rotation)
```

### How It Works

The rotation manager uses a background timer thread that triggers periodically:

1. Timer expires (e.g., after 5 minutes)
2. Rotation callback is invoked
3. Both device and platform generate new ephemeral key pairs
4. New public keys are exchanged via MQTT
5. Both sides compute new shared secret and derive new session key
6. Old session key is discarded
7. Timer is reset for the next rotation

This process ensures the session key is never transmitted over the network, even during rotation.

### Security Benefits

| Scenario | Impact |
|----------|--------|
| Key compromised at 8:05 AM | Only 5 minutes of data at risk (until 8:10 rotation) |
| Device connected for 10 hours | Uses 120 different session keys |
| Attacker records all traffic | Cannot decrypt past sessions (forward secrecy) |

---

## Testing

The implementation includes comprehensive tests in `test_r4.py`:
```bash
python test_r4.py
```

### Test Suite

1. **ECDH Handshake Test** - Verifies that device and platform derive identical session keys using X25519
2. **Classic DH Handshake Test** - Verifies that device and platform derive identical session keys using RFC 3526 DH
3. **MitM Detection Test** - Ensures handshake fails when one side uses wrong PIN (HMAC verification catches this)
4. **Invalid Algorithm Test** - Validates proper error handling for unsupported algorithms
5. **Automatic Rotation Test** - Verifies that rotation performs complete DH handshakes periodically and generates unique session keys

Expected output:
```
5/5 tests passed
🎉 All R4 tests pass!
```

---

## Files and Architecture
```
src/spea_lab_iot/key_agreement.py
├── KeyAgreement (abstract base class)
│   ├── create(algorithm, pin) - Factory method
│   ├── public_key_bytes() - Get public key for transmission
│   ├── derive_session_key(peer_pub) - Compute session key
│   ├── make_transcript_hmac(parts) - Create HMAC signature
│   └── verify_transcript_hmac(parts, hmac) - Verify HMAC signature
│
├── _DHKeyAgreement (classic DH implementation)
│   └── Uses RFC 3526 2048-bit MODP group 14
│
├── _ECDHKeyAgreement (modern ECDH implementation)
│   └── Uses X25519 elliptic curve
│
└── KeyRotationManager (automatic rotation)
    ├── start_automatic_rotation(callback) - Start timer
    ├── stop_automatic_rotation() - Stop timer
    └── get_rotation_stats() - Get timing information

test_r4.py
└── Comprehensive test suite (5 tests)
```

---
