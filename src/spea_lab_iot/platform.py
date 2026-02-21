"""
Platform manager: enrollment (pairing), allowed/enrolled devices, and data relay.

Subscribes to iot/enroll (pairing) and iot/data (device data).
Republishes accepted data to iot/feed including device_id for identification.
Console: Add device, Remove device, Toggle log mode.
"""

import base64
from dotenv import load_dotenv

load_dotenv()

import json
import os
import sys
import threading
import time

import paho.mqtt.client as mqtt

from spea_lab_iot.config import (
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_PASSWORD,
    MQTT_USER,
    PLATFORM_DEFAULT_PIN,
    TOPIC_DATA,
    TOPIC_ENROLL,
    TOPIC_ENROLL_RESPONSE,
    TOPIC_FEED,
    TOPIC_REKEY,
    TOPIC_REKEY_RESPONSE,
)
from spea_lab_iot.key_manager import KeyManager

# Imports related to cryptographic
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# Allowed devices: device_id -> pin. "default" is the platform PIN (cannot be removed).
ALLOWED_DEVICES_KEY_DEFAULT = "default"
# Enrolled devices: set of device_id that have paired and can send data.
# When removed, we stop accepting their data.

# Choose mode of Cryptography (maybe can be determinated by user using the platform)
ALGORITHM_DEFAULT = "AES-CBC"  # 'AES-GCM'
POS_ALG = ["AES-CBC", "AES-GCM"]


# ==================================================================================================



# ==================================================================================================


def _log(enable: bool, msg: str) -> None:
    if enable:
        print(f"[platform] {msg}")


# ------------------- FUNCTIONS RELATED TO CRYPTOGRAPHIC----------------------
# Function to decrypt using AEAD
def decrypt_aead_aes_gcm(key, nonce, ciphertext, tag, aad):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


# Function to decrypt using AE
def decrypt_aes_cbc(enc_key, mac_key, iv, ciphertext, tag):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    h.verify(tag)

    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext


# ----------------------------------------------------------------------------


def run_platform(log_enabled: bool = False, interactive: bool = True) -> None:
    allowed_devices: dict[str, dict] = {}
    # Add by default
    allowed_devices[ALLOWED_DEVICES_KEY_DEFAULT] = {
        "pin": PLATFORM_DEFAULT_PIN,
        "alg": ALGORITHM_DEFAULT,
    }
    enrolled_devices: set[str] = set()
    device_managers: dict[str, KeyManager] = {}
    log_mode = [log_enabled]  # use list so closure can mutate

    def on_connect(
        client: mqtt.Client,
        userdata: object,
        flags: dict,
        reason_code: int,
        properties: object | None = None,
    ) -> None:
        if reason_code == 0:
            _log(log_mode[0], f"Connected to broker {MQTT_BROKER_HOST}")
            client.subscribe(TOPIC_ENROLL, qos=1)
            client.subscribe(TOPIC_REKEY, qos=1)
            client.subscribe(TOPIC_DATA, qos=1)
        else:
            print(f"Connection failed: {reason_code}", file=sys.stderr)

    def on_enroll_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            _log(log_mode[0], "Invalid JSON on enroll topic")
            return
        action = payload.get("action")
        device_id = payload.get("device_id")
        pin = payload.get("pin")
        alg = payload.get("alg")
        if (
            action != "pairing"
            or not device_id
            or pin is None
            or alg is None
            or alg not in POS_ALG
        ):
            _log(
                log_mode[0],
                f"Ignored enroll message: action={action!r}, device_id={device_id!r}",
            )
            return
        # Accept if pin matches default or (device_id in allowed_devices and pin matches)
        platform_pin = allowed_devices.get(ALLOWED_DEVICES_KEY_DEFAULT).get("pin")

        if pin == platform_pin and allowed_devices.get(device_id) is None:
            allowed_devices[device_id] = {"pin": pin, "alg": alg}

        allowed_dict = allowed_devices.get(device_id)
        if allowed_dict is None and pin != platform_pin:
            _log(
                log_mode[0], f"Pairing rejected for device_id={device_id!r} (wrong PIN)"
            )
            return
        else:
            allowed_pin = allowed_dict.get("pin")
            if pin != platform_pin and pin != allowed_pin:
                _log(
                    log_mode[0],
                    f"Pairing rejected for device_id={device_id!r} (wrong PIN)",
                )
                return

        enrolled_devices.add(device_id)
        
        # Initialize KeyManager for the device
        km = KeyManager(device_id)
        km.derive_master_key(pin)
        device_managers[device_id] = km
        
        _log(log_mode[0], f"Device enrolled: device_id={device_id!r}")
        response = {
            "device_id": device_id,
            "status": "enrolled",
            "data_topic": TOPIC_DATA,
        }
        client.publish(TOPIC_ENROLL_RESPONSE, json.dumps(response), qos=1)

    def on_rekey_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        try:
            payload = json.loads(msg.payload.decode())
            device_id = payload.get("device_id")
            sig = payload.get("sig")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not device_id or device_id not in enrolled_devices or not sig:
            return

        km = device_managers.get(device_id)
        if not km:
            return

        # Verify signature
        payload_verify = payload.copy()
        del payload_verify["sig"]
        h = HMAC.new(km.master_key, digestmod=SHA256)
        h.update(json.dumps(payload_verify, sort_keys=True).encode())
        try:
            h.verify(base64.b64decode(sig))
        except ValueError:
            _log(log_mode[0], f"Invalid rekey signature from {device_id}")
            return

        # Generate new key
        new_key = km.generate_random_session_key()
        new_id = km.session_key_id + 1
        km.set_session_key(new_key, new_id)

        # Encrypt response with Master Key (AES-GCM)
        iv = get_random_bytes(16)
        cipher = AES.new(km.master_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(new_key)

        response = {
            "device_id": device_id,
            "key_id": new_id,
            "nonce": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "tag": base64.b64encode(tag).decode()
        }
        client.publish(TOPIC_REKEY_RESPONSE, json.dumps(response), qos=1)
        _log(log_mode[0], f"Rekey successful for {device_id}. New key ID: {new_id}")

    def on_data_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        # We obtained the payload without decrypt
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            _log(log_mode[0], "Invalid JSON on data topic")
            return

        # Check if it is valid
        device_id = payload.get("device_id")
        if not device_id:
            _log(log_mode[0], "Data message without device_id, ignored")
            return

        if device_id not in enrolled_devices:
            _log(log_mode[0], f"Ignored data from non-enrolled device_id={device_id!r}")
            return

        # Obtain the pin
        pin = allowed_devices[device_id].get("pin")

        # Obtain neccessary data to decrypt
        algorithm = payload.get("alg")
        if not algorithm or algorithm not in POS_ALG:
            _log(log_mode[0], "Data message without alg, ignored")
            return

        nonce = base64.b64decode(payload.get("nonce"))
        if not nonce:
            _log(log_mode[0], "Data message without nonce, ignored")
            return

        ciphertext = base64.b64decode(payload.get("ciphertext"))
        if not ciphertext:
            _log(log_mode[0], "Data message without ciphertext, ignored")
            return

        tag = base64.b64decode(payload.get("tag"))
        if not tag:
            _log(log_mode[0], "Data message without tag, ignored")
            return

        timestamp = payload.get("ts")
        if not timestamp:
            _log(log_mode[0], "Data message without timestamp, ignored")
            return

        # Get KeyManager
        km = device_managers.get(device_id)
        if not km or not km.session_key:
             _log(log_mode[0], f"No session key for {device_id}")
             return
             
        # Use session key from KeyManager
        session_key_bytes, key_id_stored = km.get_session_key()
        
        if algorithm == "AES-CBC":
            # AE
            enc_key = session_key_bytes[:16]
            auth_key = session_key_bytes[16:]
            plaintext = decrypt_aes_cbc(enc_key, auth_key, nonce, ciphertext, tag)

        elif algorithm == "AES-GCM":
            # AEAD
            aad = (device_id + "|" + timestamp).encode()
            # Use full 32 bytes for GCM (matching device.py)
            plaintext = decrypt_aead_aes_gcm(session_key_bytes, nonce, ciphertext, tag, aad)
        else:
            _log(log_mode[0], "Algorithm type invalid")
            return

        # Republish to iot/feed with same payload (includes device_id for identification)
        client.publish(TOPIC_FEED, plaintext, qos=1)
        _log(log_mode[0], f"Relayed data from device_id={device_id!r} to {TOPIC_FEED}")

    def on_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        if msg.topic == TOPIC_ENROLL:
            on_enroll_message(client, userdata, msg)
        elif msg.topic == TOPIC_REKEY:
            on_rekey_message(client, userdata, msg)
        elif msg.topic == TOPIC_DATA:
            on_data_message(client, userdata, msg)

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

    def console_loop() -> None:
        while True:
            print("\n--- Platform ---")
            print("1. Add device (device_id + PIN + encrypted algorithm)")
            print("2. Remove device (device_id)")
            print("3. Toggle log mode")
            print("4. Quit")
            try:
                choice = input("Choice [1-4]: ").strip() or "0"
            except (EOFError, KeyboardInterrupt):
                break
            if choice == "1":
                did = input("Device ID: ").strip()
                pin = input("PIN: ").strip()
                alg = input("Algorithm ('AES-CBC' or 'AES-GCM'): ").strip()
                if did and pin and alg:
                    if did == ALLOWED_DEVICES_KEY_DEFAULT:
                        print("Cannot add key 'default'; it is reserved.")
                    elif alg not in POS_ALG:
                        print("Encrypted algorithm only can be:" + POS_ALG)
                    else:
                        allowed_devices[did] = {"pin": pin, "alg": alg}
                        print(f"Added device_id={did!r} with PIN.")
                else:
                    print("Device ID and PIN required.")
            elif choice == "2":
                did = input("Device ID to remove: ").strip()
                if did == ALLOWED_DEVICES_KEY_DEFAULT:
                    print("Cannot remove 'default'.")
                elif did in allowed_devices:
                    del allowed_devices[did]
                    enrolled_devices.discard(did)
                    print(
                        f"Removed device_id={did!r}. It can no longer pair or send data."
                    )
                else:
                    print(f"Unknown device_id={did!r}.")
            elif choice == "3":
                log_mode[0] = not log_mode[0]
                print(f"Log mode: {'on' if log_mode[0] else 'off'}")
            elif choice == "4":
                break

    if interactive:
        try:
            console_loop()
        finally:
            client.loop_stop()
            client.disconnect()
    else:
        # Non-interactive mode (e.g. testing): Block until interrupted
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            client.loop_stop()
            client.disconnect()
    
    print("Platform stopped.")


def main() -> None:
    log_env = os.environ.get("PLATFORM_LOG", "").lower() in ("1", "true", "yes")
    run_platform(log_enabled=log_env)


if __name__ == "__main__":
    main()
