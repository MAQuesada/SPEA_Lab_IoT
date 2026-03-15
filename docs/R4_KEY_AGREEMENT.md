# R4: Key Agreement with Automatic Rotation

To ensure that session keys used for data encryption are established securely, a key agreement protocol has been implemented between devices and the platform. This prevents any third party from learning the session key, even if they observe MQTT traffic during the handshake. After a device is enrolled, it initiates a Diffie-Hellman handshake with the platform. Once the handshake is complete, both sides independently derive the same `session_key` without ever transmitting it over the network.

---

## Library

The `cryptography` library has been used to implement the key agreement mechanisms, providing robust implementations of Diffie-Hellman and ECDH algorithms.

---

## Supported Algorithms

The system supports two key agreement algorithms:

* **Classic Diffie-Hellman (auth_dh).** Uses RFC 3526 2048-bit MODP group 14 with generator 2. This algorithm is slower (~30 seconds for parameter generation) but provides wide compatibility. The shared secret is derived through modular exponentiation, and HKDF-SHA256 is applied to produce the final `session_key`.

* **Elliptic Curve Diffie-Hellman (ecdh_ephemeral).** Uses the modern X25519 elliptic curve for key agreement. This algorithm generates 256-bit ephemeral keys and is significantly faster (<1 second) than classic DH while providing equivalent security. The shared secret is derived through elliptic curve point multiplication, followed by HKDF-SHA256 to produce the `session_key`.

Both algorithms include HMAC-SHA256 authentication of the handshake transcript to prevent Man-in-the-Middle attacks, even when the MQTT broker is untrusted.

On keyboard devices, the user chooses the key agreement algorithm between `ecdh_ephemeral` or `auth_dh` after selecting the encryption algorithm. However, on screen devices, the algorithm is chosen randomly.

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

## New MQTT topics
| Topic | Publisher | Subscriber | Purpose |
|-------|-----------|------------|---------|
| `iot/dh/init` | Device | Server | Initiates the handshake, sends device public key |
| `iot/dh/response` | Server | Device | Sends platform public key and HMAC transcript |
| `iot/dh/finish` | Device | Server | Confirms handshake, sends device HMAC transcript |

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

Expected output:
```
4/4 tests passed
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
    └── Uses X25519 elliptic curve


test_r4.py
└── Comprehensive test suite (5 tests)
```

---
