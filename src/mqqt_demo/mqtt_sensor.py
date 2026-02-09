#!/usr/bin/env python3
"""
Simulates a temperature and humidity sensor publishing to an MQTT broker.

Readings are generated around a baseline with random deviation (±10°C for
temperature, ±10% for humidity) to mimic real sensor behaviour.
"""

import json
import random
import signal
import sys
import time

import paho.mqtt.client as mqtt

# Broker configuration (Shiftr.io public broker)
BROKER_HOST = "public.cloud.shiftr.io"
BROKER_PORT = 1883
BROKER_USER = "public"
BROKER_PASSWORD = "public"
TOPIC = "spea-lab-iot/sensor"
INTERVAL_SEC = 5

# Baseline values (typical room conditions). Readings will vary around these.
BASELINE_TEMPERATURE_C = 24.0
BASELINE_HUMIDITY_PCT = 55.0

# Maximum random deviation from baseline, simulating real sensor noise.
# Temperature: ±10°C, Humidity: ±10%
TEMPERATURE_DEVIATION = 10.0
HUMIDITY_DEVIATION = 10.0

# Clamp readings to physically plausible ranges
TEMP_MIN = 0.0
TEMP_MAX = 50.0
HUMIDITY_MIN = 0.0
HUMIDITY_MAX = 100.0


def on_connect(
    client: mqtt.Client,
    userdata: object,
    flags: dict,
    reason_code: int,
    properties: object | None = None,
) -> None:
    """Called when the client connects to the broker."""
    if reason_code == 0:
        print(f"Connected to broker {BROKER_HOST}")
    else:
        print(f"Connection failed: {reason_code}")


def on_publish(
    client: mqtt.Client,
    userdata: object,
    mid: int,
    reason_code: int | None = None,
    properties: object | None = None,
) -> None:
    """Called when a message has been published (optional error handling)."""
    if reason_code is not None and reason_code != 0:
        print(f"Publish failed: mid={mid}, reason_code={reason_code}")


def read_temperature() -> float:
    """
    Simulate a temperature reading: baseline + random deviation ±10°C,
    then clamped to valid range.
    """
    value = BASELINE_TEMPERATURE_C + random.uniform(
        -TEMPERATURE_DEVIATION, TEMPERATURE_DEVIATION
    )
    return round(max(TEMP_MIN, min(TEMP_MAX, value)), 1)


def read_humidity() -> float:
    """
    Simulate a humidity reading: baseline + random deviation ±10%,
    then clamped to 0–100%.
    """
    value = BASELINE_HUMIDITY_PCT + random.uniform(
        -HUMIDITY_DEVIATION, HUMIDITY_DEVIATION
    )
    return round(max(HUMIDITY_MIN, min(HUMIDITY_MAX, value)), 1)


def main() -> None:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(BROKER_USER, BROKER_PASSWORD)
    client.on_connect = on_connect
    client.on_publish = on_publish

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except Exception as e:
        print(f"Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    client.loop_start()

    running = True

    def stop(_: int, __: object | None) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)

    print(f"Publishing to topic '{TOPIC}' every {INTERVAL_SEC}s (Ctrl+C to stop)")
    while running:
        temperature = read_temperature()
        humidity = read_humidity()
        payload = {
            "temperature": temperature,
            "humidity": humidity,
            "unit_temp": "celsius",
            "unit_humidity": "%",
        }
        msg = json.dumps(payload)
        result = client.publish(TOPIC, msg, qos=1)
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            print(f"Published: temp={temperature}°C, humidity={humidity}%")
        time.sleep(INTERVAL_SEC)

    client.loop_stop()
    client.disconnect()
    print("Stopped.")


if __name__ == "__main__":
    main()
