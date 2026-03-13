"""
Subscriber to iot/feed: receives data relayed by the platform (includes device_id).
Subscriber to iot/data: receives RAW encrypted data to demonstrate R5 encryption.
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
    TOPIC_DATA,  # Añadimos el canal de datos crudos
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
        # Nos suscribimos a ambos canales
        client.subscribe(TOPIC_FEED, qos=1)
        client.subscribe(TOPIC_DATA, qos=1)
        
        print(f"🎧 Subscribed to public channel (RAW Encrypted): '{TOPIC_DATA}'")
        print(f"✅ Subscribed to private channel (Decrypted Feed): '{TOPIC_FEED}'")
        print("(Ctrl+C to stop)\n")
        print("-" * 70)
    else:
        print(f"Connection failed: {reason_code}", file=sys.stderr)


def on_message(client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage) -> None:
    try:
        payload_str = msg.payload.decode()
        
        if msg.topic == TOPIC_DATA:
            # Requisito R5: Mostramos la basura ininteligible que viaja por la red
            print(f"🔒 [iot/data RAW] -> {payload_str}")
            
        elif msg.topic == TOPIC_FEED:
            # Datos limpios y descifrados tras pasar por la Plataforma (Gateway)
            payload = json.loads(payload_str)
            device_id = payload.get("device_id", "?")
            temp = payload.get("temperature", "?")
            humidity = payload.get("humidity", "?")
            print(
                f"🟢 [iot/feed CLEAR] -> device_id={device_id!r}, temperature={temp}°C, humidity={humidity}%"
            )
            print("-" * 70)
            
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