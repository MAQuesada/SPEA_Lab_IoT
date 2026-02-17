"""
Enrollable device: pairing (keypad or screen mode) then publish sensor data.

Keypad: user enters platform PIN; device sends pairing once and waits for enrollment.
Screen: device displays its ID and PIN, retries pairing until enrolled.
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
)

# imports related to cryptography
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

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

# Choose mode of Cryptography (maybe can be determinated by user using the platform)
# ALGORITHM = 'AES-CBC'
ALGORITHM = "AES-GCM"
POS_ALG = ["AES-CBC", "AES-GCM"]


# ==================================================================================================
# TEMPORAL KEY -> WHEN AUTHENTICATED METHODS will be IMPLEMENTED, THEN THIS IS GOING TO BE ERASED
def derive_key_from_pin(pin: str):
    salt = b"iot-mock-salt"
    iterations = 100_000

    key = PBKDF2(
        password=pin,
        salt=salt,
        dkLen=32,  # 256-bit key
        count=iterations,
        hmac_hash_module=SHA256,
    )

    return key


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
# Function to encrypt data using AEAD.
def encrypt_aead_aes_gcm(key: bytes, plaintext: bytes, aad: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return cipher.nonce, ciphertext, tag


# Function to encrypt using AE
def encrypt_aes_cbc_hmac(enc_key: bytes, mac_key: bytes, plaintext: bytes):
    iv = get_random_bytes(16)

    # Create the cipher and encript it
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Added hmac
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    tag = h.digest()

    return iv, ciphertext, tag


# ---------------------------------------------------------------------------


def run_device(
    sensor_id: str,
    ui_mode: str,
    pin: str,
    alg: str | None = None,
) -> None:
    """
    Run device: pair with platform then publish temperature/humidity.

    ui_mode: "keypad" (user enters platform PIN) or "screen" (device shows ID and PIN, retries until enrolled).
    pin: for keypad, pass None and user will be prompted; for screen, pass the PIN (e.g. from env in device_screen.py).
    """
    if ui_mode == "keypad" and pin is None and alg is None:
        pin = input("Enter platform code: ").strip()
        alg = input("Enter encrypted algorithm (AES-CBC or AES-GCM): ").strip()
        if not pin:
            print("PIN required.", file=sys.stderr)
            sys.exit(1)
        if not alg or alg not in POS_ALG:
            print("Algorithm required and it should be: " + POS_ALG, file=sys.stderr)
            sys.exit(1)

    elif ui_mode == "screen":
        if not pin:
            print(
                "Screen device requires a PIN (pass pin= or set DEVICE_PAIRING_CODE in device_screen).",
                file=sys.stderr,
            )
            sys.exit(1)
        if not alg:
            print("Screen device requires an encrypted algorithm", file=sys.stderr)
        print(f"Device ID: {sensor_id}")
        print(f"PIN: {pin}")
        print(f"Encrypted algorithm: {alg}")
        print("Attempting pairing until enrolled...")
    else:
        print("ui_mode must be 'keypad' or 'screen'.", file=sys.stderr)
        sys.exit(1)

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

    def on_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        if msg.topic != TOPIC_ENROLL_RESPONSE:
            return
        try:
            payload = json.loads(msg.payload.decode())
            print(f"Payload: {payload}")
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

    # Pairing phase
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

    data_topic = data_topic_ref[0] or TOPIC_DATA
    print(f"Enrolled. Publishing data to {data_topic} (Ctrl+C to stop)")

    running = True

    def stop(_: int, __: object | None) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)

    while running:
        temperature = _read_temperature()
        humidity = _read_humidity()
        payload = {
            "device_id": sensor_id, 
            "temperature": temperature,
            "humidity": humidity,
            "unit_temp": "celsius",
            "unit_humidity": "%",
        }

        # Convert to plaintext
        plaintext = json.dumps(payload).encode()

        # Obtain some metadata
        timestamp = str(int(time.time()))
        aad = (sensor_id + "|" + timestamp).encode()

        # =================MOCKS PROVISIONALES =====================
        key = derive_key_from_pin(pin)
        session_key = key[:16]
        auth_key = key[16:]
        key_id = 1
        # ============================================================================================

        if alg == "AES-CBC":
            # AE
            nonce, ciphertext, tag = encrypt_aes_cbc_hmac(
                session_key, auth_key, plaintext
            )
        elif alg == "AES-GCM":
            # AEAD
            nonce, ciphertext, tag = encrypt_aead_aes_gcm(session_key, plaintext, aad)
        else:
            print("ERROR: unknown algorithm", file=sys.stderr)
            sys.exit(1)

        # Create new payload
        encrypted_payload = {
            "device_id": sensor_id,
            "key_id": key_id,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode(),
            "alg": alg,
            "ts": timestamp,
        }

        client.publish(data_topic, json.dumps(encrypted_payload), qos=1)
        print(
            f"Published: device_id={sensor_id!r}, temp={temperature}°C, humidity={humidity}%"
        )
        print(f"Encrypted message: {encrypted_payload}")
        time.sleep(DATA_INTERVAL_SEC)

    client.loop_stop()
    client.disconnect()
    print("Device stopped.")
