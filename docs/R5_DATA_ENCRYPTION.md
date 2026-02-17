# R5: Data encryption

To ensure that the data from our devices is not visible to third parties, encryption of the original payload has been added. To achieve this, when devices are paired with `action: "pairing"`, an encryption algorithm is also determined. After that, the devices publish to `iot/data`, encrypting the data using `auth_key` as the authentication key and `session_key` as the encryption key. Subsequently, the platform decrypts the data and sends it to the subscribers for display.

---

## Library

To implement the encryption process, the `PyCryptodome` library has been used, as it is well known in academic environments and its steps are easy to understand.

---

## Types of Encryption

* **Authenticated Encryption (AE): AES-CBC.** This focuses only on encrypting the original payload with the `session_key`, and then authenticating that ciphertext using `auth_key` as the MAC. Specifically, the chosen algorithm is **AES_CBC_HMAC**. The decryption process occurs in a similar but reverse manner: first verifying that the result is correct, and then decrypting. 

* **Authenticated Encryption with Associated Data (AEAD): AES-GCM.** This adds device-related metadata to the encryption mechanism. The metadata includes `device_id` and `timestamp`. The data is then encrypted using only the `session_key`. The decryption process works similarly but in reverse, incorporating the metadata into the encryption mechanism and decrypting based on it.

#### Summary
| Cryptographic Algorithms | Type of Encryption | Keys |
|--------------------------|--------------------|------|
| `AES-CBC` | AE | `auth_key` and `session_key` | 
| `AES-GCM` | AEAD | `session_key` |

---

## Implemented changes according to R1: Step by Step

### Step 1: Choose Encrypted Algorithm

#### Step 1a: Keypad device

After entering the **platform default PIN**, enter the desired encryption algorithm. You can choose between `AES-CBC` or `AES-CBC`. The device pairs once. 

#### Step 1b: Screen device

1. **Run the screen device**. Besides generating a random 6-digit PIN, it selects a random encryption algorithm. Now, you will see e.g. `Device ID: sensor-screen-01`, `PIN: 483921` `Encrypted algorithm: AES-CBC`, and "Attempting pairing until enrolled...".

2. **Add the device on the platform**
   Now, in the platform console: **1. Add device**, you should enter:
   - Device ID: `sensor-screen-01` (match `SENSOR_ID` in `device_screen.py`)
   - PIN: the 6-digit value shown on the device (e.g. `483921`).
   - **Algorithm (new implementation)**: the encryption algorithm (e.g. `AES-CBC`)

   The device’s next pairing attempt will succeed

### Step 2: Publish encrypted data by device

When the payload is created as a JSON, it is transformed into plain text. In addition, the metadata (`timestamp` and `aad`) is generated. Then, according to the previously determined encryption algorithm, that plaintext is encrypted.

Finally, the following JSON is published to `iot/data`:
```
{
    "device_id", 
    "key_id", 
    "nonce", # iv from AES-CBC or nonce from AES-GCM
    "ciphertext", # encrypted payload
    "tag", # Data to authenticate the ciphertext
    "alg", # Encryption algorithm
    "ts", # Timestamp
}
```

### Step 3: Recive and decrypt data by platform

When the platform receives the encrypted message, it first verifies that all the fields match the values it has stored. Then, it decrypts the ciphertext using the received data and its own key associated with the device. This text is send to the subscribers.

---

ANNOTATION -> MAYBE AFTER THE IMPLEMENTATION OF KEYS, THIS DOCUMENTATION HAS SEVERAL CHANGES
