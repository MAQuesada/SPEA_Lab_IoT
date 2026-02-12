"""
Platform manager: enrollment (pairing), allowed/enrolled devices, and data relay.

Subscribes to iot/enroll (pairing) and iot/data (device data).
Republishes accepted data to iot/feed including device_id for identification.
Console: Add device, Remove device, Toggle log mode.
"""

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
)

# Allowed devices: device_id -> pin. "default" is the platform PIN (cannot be removed).
ALLOWED_DEVICES_KEY_DEFAULT = "default"
# Enrolled devices: set of device_id that have paired and can send data.
# When removed, we stop accepting their data.


def _log(enable: bool, msg: str) -> None:
    if enable:
        print(f"[platform] {msg}")


def run_platform(log_enabled: bool = False) -> None:
    allowed_devices: dict[str, str] = {
        ALLOWED_DEVICES_KEY_DEFAULT: PLATFORM_DEFAULT_PIN
    }
    enrolled_devices: set[str] = set()
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
        if action != "pairing" or not device_id or pin is None:
            _log(
                log_mode[0],
                f"Ignored enroll message: action={action!r}, device_id={device_id!r}",
            )
            return
        # Accept if pin matches default or (device_id in allowed_devices and pin matches)
        platform_pin = allowed_devices.get(ALLOWED_DEVICES_KEY_DEFAULT)
        allowed_pin = allowed_devices.get(device_id)
        if pin != platform_pin and (allowed_pin is None or pin != allowed_pin):
            _log(
                log_mode[0], f"Pairing rejected for device_id={device_id!r} (wrong PIN)"
            )
            return
        # Keypad devices pair with platform PIN; add to allowed_devices so they can be removed later
        if device_id not in allowed_devices:
            allowed_devices[device_id] = pin
        enrolled_devices.add(device_id)
        _log(log_mode[0], f"Device enrolled: device_id={device_id!r}")
        response = {
            "device_id": device_id,
            "status": "enrolled",
            "data_topic": TOPIC_DATA,
        }
        client.publish(TOPIC_ENROLL_RESPONSE, json.dumps(response), qos=1)

    def on_data_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            _log(log_mode[0], "Invalid JSON on data topic")
            return
        device_id = payload.get("device_id")
        if not device_id:
            _log(log_mode[0], "Data message without device_id, ignored")
            return
        if device_id not in enrolled_devices:
            _log(log_mode[0], f"Ignored data from non-enrolled device_id={device_id!r}")
            return
        # Republish to iot/feed with same payload (includes device_id for identification)
        client.publish(TOPIC_FEED, msg.payload, qos=1)
        _log(log_mode[0], f"Relayed data from device_id={device_id!r} to {TOPIC_FEED}")

    def on_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        if msg.topic == TOPIC_ENROLL:
            on_enroll_message(client, userdata, msg)
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
            print("1. Add device (device_id + PIN)")
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
                if did and pin:
                    if did == ALLOWED_DEVICES_KEY_DEFAULT:
                        print("Cannot add key 'default'; it is reserved.")
                    else:
                        allowed_devices[did] = pin
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

    try:
        console_loop()
    finally:
        client.loop_stop()
        client.disconnect()
    print("Platform stopped.")


def main() -> None:
    log_env = os.environ.get("PLATFORM_LOG", "").lower() in ("1", "true", "yes")
    run_platform(log_enabled=log_env)


if __name__ == "__main__":
    main()
