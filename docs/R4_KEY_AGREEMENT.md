# R4: Key Agreement

To ensure that the session keys used for data encryption are established securely, a key agreement protocol has been added between devices and the platform. This prevents any third party from learning the session key, even if they observe the MQTT traffic during the handshake. After a device is enrolled, it immediately initiates a Diffie-Hellman handshake with the platform. Once the handshake is complete, both sides independently derive the same `session_key` and `auth_key` using HKDF, without ever transmitting them over the network.

---

## Algorithms

| Algorithm | Type | Authentication | Keys Derived |
|-----------|------|---------------|--------------|
| **`ecdh_ephemeral`** | ECDH (P-256), ephemeral | HMAC transcript | `session_key` and `auth_key` |
| **`auth_dh`** | DH + PIN | HMAC transcript + PIN | `session_key` and `auth_key` |

The default algorithm for all devices is `ecdh_ephemeral`. It is selected when the operator adds the device on the platform.

---

## Key Agreement Handler (`key_agreement.py`)

All key agreement logic is centralised in the `KeyAgreement` class. Each device and the platform run one instance per device, identified by `device_id`.

Key operations:

- `generate_keypair()` — generates an ephemeral key pair for the handshake.
- `compute_shared_secret(peer_public_key)` — computes the DH shared secret from the peer's public key.
- `derive_keys(shared_secret)` — runs HKDF on the shared secret to produce `session_key` and `auth_key`.
- `compute_hmac_transcript(...)` — computes the HMAC of the handshake transcript for mutual verification.
- `verify_hmac_transcript(...)` — verifies the transcript received from the peer.

---

## Handshake flow

The handshake uses three MQTT messages and completes in one round trip:

### Step 1 — Device sends init

After enrollment, the device generates an ephemeral key pair and publishes to `iot/dh/init`:

```json
{
    "device_id": "sensor-keypad-01",
    "algorithm": "ecdh_ephemeral",
    "public_key": "<base64-encoded ephemeral public key>"
}
```

### Step 2 — Platform responds

The platform generates its own ephemeral key pair, computes the shared secret, and derives `session_key` and `auth_key` via HKDF. It then publishes to `iot/dh/response`:

```json
{
    "device_id": "sensor-keypad-01",
    "public_key": "<base64-encoded platform ephemeral public key>",
    "hmac_transcript": "<base64-encoded HMAC of the handshake transcript>"
}
```

### Step 3 — Device finishes

The device computes the same shared secret, derives the same keys, and verifies the `hmac_transcript` received from the platform. If valid, it publishes to `iot/dh/finish`:

```json
{
    "device_id": "sensor-keypad-01",
    "hmac_transcript": "<base64-encoded HMAC from the device side>"
}
```

The platform verifies this final transcript to confirm both sides hold the same keys. The handshake is now complete:

```
[platform] DH response sent to device_id='sensor-keypad-01' (algorithm=ecdh_ephemeral)
[platform] Handshake complete for device_id='sensor-keypad-01' — session_key=e093f76f096c95e0...
[platform] KeyManager initialized with DH session key for 'sensor-keypad-01'
```

---

## New MQTT topics

Three new topics have been added alongside the existing ones from R1:

| Topic | Publisher | Subscriber | Purpose |
|-------|-----------|------------|---------|
| `iot/dh/init` | Device | Platform | Initiates the handshake, sends device public key |
| `iot/dh/response` | Platform | Device | Sends platform public key and HMAC transcript |
| `iot/dh/finish` | Device | Platform | Confirms handshake, sends device HMAC transcript |

---

## Session key derivation

After the shared secret is computed, **HKDF** (HMAC-based Key Derivation Function) is applied to derive two independent 256-bit keys:

| Key | Purpose |
|-----|---------|
| `session_key` | Encrypts all sensor data (used in R5) |
| `auth_key` | Authenticates the ciphertext in AES-CBC mode (used in R5) |

> **Note**: In a real deployment, the device's long-term identity would be verified using a certificate or a pre-shared asymmetric key. Here, mutual authentication is achieved via the HMAC transcript, which proves that both sides computed the same shared secret.