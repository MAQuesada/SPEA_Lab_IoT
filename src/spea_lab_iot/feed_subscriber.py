"""
Subscriber to iot/feed: receives data relayed by the platform (includes device_id).
"""

from dotenv import load_dotenv

load_dotenv()

import json
import sys

import paho.mqtt.client as mqtt

from spea_lab_iot.config import (
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_PASSWORD,
    MQTT_USER,
    TOPIC_FEED,
)


def on_connect(
    client: mqtt.Client,
    userdata: object,
    flags: dict,
    reason_code: int,
    properties: object | None = None,
) -> None:
    if reason_code == 0:
        print(f"Connected to broker {MQTT_BROKER_HOST}")
        client.subscribe(TOPIC_FEED, qos=1)
        print(f"Subscribed to topic '{TOPIC_FEED}' (Ctrl+C to stop)\n")
    else:
        print(f"Connection failed: {reason_code}", file=sys.stderr)


def on_message(client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage) -> None:
    try:
        payload = json.loads(msg.payload.decode())
        device_id = payload.get("device_id", "?")
        temp = payload.get("temperature", "?")
        humidity = payload.get("humidity", "?")
        print(
            f"Received: device_id={device_id!r}, temperature={temp}°C, humidity={humidity}%"
        )
        print(f"  Raw payload: {payload}")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Received (raw): {msg.payload!r} (parse error: {e})")


def main() -> None:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    client.loop_forever()


if __name__ == "__main__":
    main()
