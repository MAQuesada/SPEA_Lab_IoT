# SPEA Lab IoT: Secure Pub/Sub Architecture (Release Version)

This project implements a secure, end-to-end IoT infrastructure using MQTT. It surpasses the basic publish/subscribe model by integrating dynamic enrollment, authenticated key exchange, automatic key rotation, and a central Gateway that feeds a real-time Web Dashboard.

---

## System Architecture

The ecosystem consists of five main orchestrated modules running concurrently:

- `server.py` — Acts as the security Gateway and central authority. Manages the allowed devices whitelist, negotiates cryptographic keys, and decrypts valid telemetry to relay it to secure channels.
- `dashboard.py` — A command center built with Streamlit. Allows visual administration of the device lifecycle (adding/removing sensors) and monitors decrypted telemetry in real-time time-series charts.
- `device.py` — The core, headless IoT engine. Manages MQTT connections, cryptography (R2-R3, R4, R5), and self-healing resilience independently from the UI.
- `device_keypad.py` & `device_screen.py` — "Immortal" UI terminals. They handle user inputs, auto-discover IDs from PINs, and stay alive even if the platform revokes their access, acting as the "steering wheel" for the engine.
- `device_no_ui.py` — Device with no user interface. Since the information is not displayed to the user, it uses a default ID, encryption algorithm, and key agreement algorithm, along with the platform's PIN for connection. This device is automatically added to the platform due to its special conditions.
- `device_menu.py` — A unified interactive launcher to easily spawn additional Keypad or Screen devices on demand.

---

## Security Requirements & Implementation

### R1: Device Enrollment and Access Control
The only device which can publish data without prior authorization is the No UI mode. The rest can't publish data without prior authorization. The platform maintains a dictionary of allowed devices. Devices pair using `action: "pairing"` and a PIN.
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
| **`AES-CBC`** | Authenticated Encryption (AE) | Split: `enc_key` (encrypt) and `mac_key` (MAC) |
| **`AES-GCM`** | AEAD | Full `session_key` (incorporates `device_id`, `timestamp` and `key_id` as AAD) |

---

## Quick Start (One-Click Launch)

This project includes an orchestrator script that boots the entire ecosystem simultaneously.

### Step 1: Install dependencies

From the project root:

```bash
uv sync
```
## Step 2: Run the master launcher
```bash
uv run python -m start_lab.py
```
