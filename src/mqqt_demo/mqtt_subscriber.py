#!/usr/bin/env python3
"""
MQTT client that subscribes to the sensor topic and prints received payloads.

Expects JSON messages with 'temperature' and 'humidity' fields.
"""

import json
import sys

import paho.mqtt.client as mqtt

# Broker configuration (must match the sensor)
BROKER_HOST = "public.cloud.shiftr.io"
BROKER_PORT = 1883
BROKER_USER = "public"
BROKER_PASSWORD = "public"
TOPIC = "spea-lab-iot/sensor"


def on_connect(
    client: mqtt.Client,
    userdata: object,
    flags: dict,
    reason_code: int,
    properties: object | None = None,
) -> None:
    """Called when connected to the broker. Subscribe to the topic here."""
    if reason_code == 0:
        print(f"Connected to broker {BROKER_HOST}")
        client.subscribe(TOPIC, qos=1)
        print(f"Subscribed to topic '{TOPIC}' (Ctrl+C to stop)\n")
    else:
        print(f"Connection failed: {reason_code}", file=sys.stderr)


def on_message(client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage) -> None:
    """Called when a message is received. Decode JSON and print temperature/humidity."""
    try:
        payload = json.loads(msg.payload.decode())
        temp = payload.get("temperature", "?")
        humidity = payload.get("humidity", "?")
        print(f"Received: temperature={temp}°C, humidity={humidity}%")
        print(f"  Raw payload: {payload}")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Received (raw): {msg.payload!r} (parse error: {e})")


def main() -> None:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(BROKER_USER, BROKER_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    # Block until disconnected (e.g. Ctrl+C)
    client.loop_forever()


if __name__ == "__main__":
    main()
