"""
Enrollable device: pairing (keypad or screen mode) then publish sensor data.

Keypad: user enters platform PIN; device sends pairing once and waits for enrollment.
Screen: device displays its ID and PIN, retries pairing until enrolled.

After enrollment:
  - R4: performs authenticated DH key agreement to derive session_key and auth_key
  - R2-R3: KeyManager uses the DH-derived session_key and handles rotation
  - R5: encrypts data with session_key before publishing
"""

import base64
import json
import random
import signal
import sys
import threading
import time

import paho.mqtt.client as mqtt

from spea_lab_iot.config import (
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_PASSWORD,
    MQTT_USER,
    TOPIC_DATA,
    TOPIC_ENROLL,
    TOPIC_ENROLL_RESPONSE,
    TOPIC_REKEY,
    TOPIC_REKEY_RESPONSE,
)
from spea_lab_iot.key_manager import KeyManager
from spea_lab_iot.dh_device import run_dh_handshake

# imports related to cryptography
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad

# Sensor simulation (baseline + deviation)
BASELINE_TEMPERATURE_C = 24.0
BASELINE_HUMIDITY_PCT = 55.0
TEMPERATURE_DEVIATION = 10.0
HUMIDITY_DEVIATION = 10.0
TEMP_MIN = 0.0
TEMP_MAX = 50.0
HUMIDITY_MIN = 0.0
HUMIDITY_MAX = 100.0
DATA_INTERVAL_SEC = 5
PAIRING_RETRY_SEC = 3
ENROLL_WAIT_TIMEOUT_SEC = 30

POS_ALG = ["AES-CBC", "AES-GCM"]
DEFAULT_KA_ALGORITHM = "ecdh_ephemeral"  # or "auth_dh"


# ==================================================================================================
# ==================================================================================================


def _read_temperature() -> float:
    value = BASELINE_TEMPERATURE_C + random.uniform(
        -TEMPERATURE_DEVIATION, TEMPERATURE_DEVIATION
    )
    return round(max(TEMP_MIN, min(TEMP_MAX, value)), 1)


def _read_humidity() -> float:
    value = BASELINE_HUMIDITY_PCT + random.uniform(
        -HUMIDITY_DEVIATION, HUMIDITY_DEVIATION
    )
    return round(max(HUMIDITY_MIN, min(HUMIDITY_MAX, value)), 1)


# ---------------------------FUNCTIONS RELATED TO CRYPTOGRAPHY------------------

def encrypt_aead_aes_gcm(key: bytes, plaintext: bytes, aad: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag


def encrypt_aes_cbc_hmac(enc_key: bytes, mac_key: bytes, plaintext: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    tag = h.digest()
    return iv, ciphertext, tag


# ---------------------------------------------------------------------------


def run_device(
    sensor_id: str,
    ui_mode: str,
    pin: str | None = None,
    alg: str | None = None,
    ka_algorithm: str = DEFAULT_KA_ALGORITHM,
) -> None:
    """
    Run device: pair with platform, perform DH key agreement, then publish data.

    ui_mode     : "keypad" or "screen"
    pin         : platform PIN (prompted if None in keypad mode)
    alg         : encryption algorithm "AES-CBC" or "AES-GCM" (prompted if None in keypad mode)
    ka_algorithm: DH algorithm "ecdh_ephemeral" (default) or "auth_dh"
    """
    if ui_mode == "keypad":
        # If PIN or algorithm not provided, prompt interactively
        if pin is None:
            pin = input("Enter platform code: ").strip()
        if alg is None:
            alg = input("Enter encrypted algorithm (AES-CBC or AES-GCM): ").strip()
        if not pin:
            print("PIN required.", file=sys.stderr)
            sys.exit(1)
        if not alg or alg not in POS_ALG:
            print("Algorithm required. Options: " + str(POS_ALG), file=sys.stderr)
            sys.exit(1)
    elif ui_mode == "screen":
        if not pin:
            print("Screen device requires a PIN.", file=sys.stderr)
            sys.exit(1)
        if not alg:
            print("Screen device requires an encryption algorithm.", file=sys.stderr)
            sys.exit(1)
        print(f"Device ID: {sensor_id}")
        print(f"PIN: {pin}")
        print(f"Encrypted algorithm: {alg}")
        print("Attempting pairing until enrolled...")
    else:
        print("ui_mode must be 'keypad' or 'screen'.", file=sys.stderr)
        sys.exit(1)

    key_mgr = KeyManager(sensor_id)
    key_mgr.derive_master_key(pin)
    if not key_mgr.load_keys():
        print("No previous keys found or failed to load. Waiting for DH handshake.")

    enrolled_event = threading.Event()
    data_topic_ref: list[str | None] = [None]

    def on_connect(
        client: mqtt.Client,
        userdata: object,
        flags: dict,
        reason_code: int,
        properties: object | None = None,
    ) -> None:
        if reason_code == 0:
            client.subscribe(TOPIC_ENROLL_RESPONSE, qos=1)
            client.subscribe(TOPIC_REKEY_RESPONSE, qos=1)

    def on_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        if msg.topic == TOPIC_REKEY_RESPONSE:
            try:
                payload = json.loads(msg.payload.decode())
                if payload.get("device_id") != sensor_id:
                    return
                
                # Decrypt new session key
                nonce = base64.b64decode(payload["nonce"])
                tag = base64.b64decode(payload["tag"])
                ciphertext = base64.b64decode(payload["ciphertext"])
                key_id = payload["key_id"]
                
                cipher = AES.new(key_mgr.master_key, AES.MODE_GCM, nonce=nonce)
                new_session_key = cipher.decrypt_and_verify(ciphertext, tag)
                
                key_mgr.set_session_key(new_session_key, key_id)
                print(f"Key rotation successful. New Key ID: {key_id}")
                
            except Exception as e:
                print(f"Error handling rekey response: {e}")
            return

        if msg.topic != TOPIC_ENROLL_RESPONSE:
            return
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if payload.get("device_id") != sensor_id or payload.get("status") != "enrolled":
            return
        data_topic_ref[0] = payload.get("data_topic", TOPIC_DATA)
        enrolled_event.set()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    client.loop_start()

    def send_pairing() -> None:
        payload = json.dumps(
            {"action": "pairing", "device_id": sensor_id, "pin": pin, "alg": alg}
        )
        client.publish(TOPIC_ENROLL, payload, qos=1)

    # ---------------------------------------------------------------------- #
    # Phase 1 — Enrollment (R1)                                               #
    # ---------------------------------------------------------------------- #
    if ui_mode == "keypad":
        send_pairing()
        if not enrolled_event.wait(timeout=ENROLL_WAIT_TIMEOUT_SEC):
            print("Enrollment timeout. Check platform and PIN.", file=sys.stderr)
            client.loop_stop()
            client.disconnect()
            sys.exit(1)
    else:
        while not enrolled_event.is_set():
            send_pairing()
            enrolled_event.wait(timeout=PAIRING_RETRY_SEC)

    # ---------------------------------------------------------------------- #
    # Phase 2 — Key agreement (R4)                                            #
    # ---------------------------------------------------------------------- #
    print(f"Enrolled. Starting DH key agreement (algorithm={ka_algorithm})...")
    try:
        session_key, auth_key = run_dh_handshake(
            client=client,
            device_id=sensor_id,
            pin=pin,
            algorithm=ka_algorithm,
        )
    except RuntimeError as e:
        print(f"Key agreement failed: {e}", file=sys.stderr)
        client.loop_stop()
        client.disconnect()
        sys.exit(1)

    # R2-R3: initialize KeyManager with DH-derived session key
    key_mgr.set_session_key(session_key, key_id=0)
    print(f"Session key established: {session_key.hex()[:16]}...")
    print(f"Auth key established:    {auth_key.hex()[:16]}...")

    # ---------------------------------------------------------------------- #
    # Phase 3 — Data publishing (R5)                                          #
    # ---------------------------------------------------------------------- #
    data_topic = data_topic_ref[0] or TOPIC_DATA
    print(f"Publishing data to {data_topic} (Ctrl+C to stop)")

    running = True

    def stop(_: int, __: object | None) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)

    while running:
        # Check if we need to rotate keys
        if key_mgr.check_rotation_needed():
            timestamp = str(int(time.time()))
            payload_dict = {"device_id": sensor_id, "ts": timestamp}
            # Authenticate rekey request with Master Key
            h = HMAC.new(key_mgr.master_key, digestmod=SHA256)
            h.update(json.dumps(payload_dict, sort_keys=True).encode())
            payload_dict["sig"] = base64.b64encode(h.digest()).decode()

            client.publish(TOPIC_REKEY, json.dumps(payload_dict), qos=1)
            print("Invoked key rotation...")

            # Always wait for the new key before publishing,
            # regardless of whether we had an existing session key.
            # If we published with the old key while the platform already
            # switched to the new one, AES-GCM MAC check would fail.
            time.sleep(2)
            continue

        temperature = _read_temperature()
        humidity    = _read_humidity()
        payload = {
            "device_id":    sensor_id,
            "temperature":  temperature,
            "humidity":     humidity,
            "unit_temp":    "celsius",
            "unit_humidity": "%",
        }

        plaintext = json.dumps(payload).encode()
        timestamp = str(int(time.time()))
        aad = (sensor_id + "|" + timestamp).encode()

        try:
            session_key_bytes, key_id = key_mgr.get_session_key()
            
            if alg == "AES-CBC":
                # Split 32-byte key into 16 enc + 16 auth
                enc_key = session_key_bytes[:16]
                auth_key = session_key_bytes[16:]
                nonce, ciphertext, tag = encrypt_aes_cbc_hmac(
                    enc_key, auth_key, plaintext
                )
            elif alg == "AES-GCM":
                # Use full 32-byte key for AES-256-GCM
                nonce, ciphertext, tag = encrypt_aead_aes_gcm(session_key_bytes, plaintext, aad)
            else:
                print("ERROR: unknown algorithm", file=sys.stderr)
                sys.exit(1)

            encrypted_payload = {
                "device_id":  sensor_id,
                "key_id":     key_id,
                "nonce":      base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag":        base64.b64encode(tag).decode(),
                "alg":        alg,
                "ts":         timestamp,
            }

            client.publish(data_topic, json.dumps(encrypted_payload), qos=1)
            print(f"Published: device_id={sensor_id!r}, temp={temperature}°C, humidity={humidity}%")

        except ValueError as e:
            print(f"Waiting for key... ({e})")

        time.sleep(DATA_INTERVAL_SEC)

    client.loop_stop()
    client.disconnect()
    print("Device stopped.")