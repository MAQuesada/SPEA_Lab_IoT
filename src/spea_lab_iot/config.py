"""Configuration from environment variables and topic names."""

import os

from dotenv import load_dotenv

load_dotenv()

MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "public.cloud.shiftr.io")
MQTT_BROKER_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "public")
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD", "public")

# Topics
TOPIC_ENROLL = "iot/enroll"
TOPIC_ENROLL_RESPONSE = "iot/enroll/response"
TOPIC_REKEY = "iot/rekey"
TOPIC_REKEY_RESPONSE = "iot/rekey/response"
TOPIC_DATA = "iot/data"
TOPIC_FEED = "iot/feed"

# Platform: default PIN for keypad devices (cannot be deleted)
PLATFORM_DEFAULT_PIN = os.environ.get("PLATFORM_DEFAULT_PIN", "platform-pin")
