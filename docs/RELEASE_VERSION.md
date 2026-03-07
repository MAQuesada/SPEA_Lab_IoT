# SPEA Lab IoT: Secure Pub/Sub Architecture (Release Version)

This project implements a secure, end-to-end IoT infrastructure using MQTT. It surpasses the basic publish/subscribe model by integrating dynamic enrollment, authenticated key exchange, automatic key rotation, and a central Gateway that feeds a real-time Web Dashboard.

---

## System Architecture

The ecosystem consists of four main orchestrated modules running concurrently:

- `server.py` — Acts as the security Gateway and central authority. Manages the allowed devices whitelist, negotiates cryptographic keys, and decrypts valid telemetry to relay it to secure channels.
- `dashboard.py` — A command center built with Streamlit. Allows visual administration of the device lifecycle (adding/removing sensors) and monitors decrypted telemetry in real-time time-series charts.
- `device.py` — Simulated sensor nodes supporting two interface modes (Keypad and Screen). They feature active resilience (self-healing) against access revocations and network drops.
- `feed_subscriber.py` — A demonstration client that consumes the final plaintext data from the `iot/feed` topic.

---

## Security Requirements & Implementation

### R1: Device Enrollment and Access Control
No device can publish data without prior authorization. The platform maintains a dictionary of allowed devices. Devices pair using `action: "pairing"` and a PIN.
- **Keypad Mode**: The user enters the platform's default PIN into the device console to pair.
- **Screen Mode**: The device generates a random 6-digit PIN at startup. The administrator must approve this device by entering the PIN and preferred encryption algorithm into the Web Dashboard.

### R2 & R3: Key Management and Resilience
To ensure secure communication, a two-layer key management system is implemented.

| Feature | Implementation | Purpose |
|---------|----------------|---------|
| **Master Key** | PBKDF2-SHA256 (100,000 iterations) | Authenticates key rotation requests. |
| **Rotation** | Time (60s) or Message count (100) limit | Automatically requests new session keys via `iot/rekey` with HMAC. |
| **Self-Healing** | Timeout fallback & Revocation listening | If a device is removed via the Web Dashboard, it safely aborts, clears its memory, and generates a new secure PIN. |

### R4: Authenticated Key Agreement
To ensure session keys are established securely without transmitting them over the network.

| Algorithm | Type | MitM Protection |
|-----------|------|-----------------|
| **`ecdh_ephemeral`** | ECDH (P-256) | HMAC transcript verification |
| **`auth_dh`** | DH + PIN | HMAC transcript verification |

### R5: Encrypted Data Publishing
Original payloads are encrypted before being published to `iot/data`.

| Encryption Algorithm | Type | Keys Used |
|----------------------|------|-----------|
| **`AES-CBC`** | Authenticated Encryption (AE) | Split: `session_key` (encrypt) and `auth_key` (MAC) |
| **`AES-GCM`** | AEAD | Full `session_key` (incorporates `device_id` and `timestamp` as AAD) |

---

## Quick Start (One-Click Launch)

This project includes an orchestrator script that boots the entire ecosystem simultaneously.

### Step 1: Install dependencies

From the project root:s

```bash
uv sync
```
## Step 2: Run the master launcher
```bash
python start_lab.py
```
