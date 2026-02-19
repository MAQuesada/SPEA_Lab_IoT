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
TOPIC_DATA = "iot/data"
TOPIC_FEED = "iot/feed"

# Platform: default PIN for keypad devices (cannot be deleted)
PLATFORM_DEFAULT_PIN = os.environ.get("PLATFORM_DEFAULT_PIN", "platform-pin")

# Key agreement topics (R4)
TOPIC_DH_INIT     = "iot/dh/init"      # device -> platform  {device_id, algorithm, public_key}
TOPIC_DH_RESPONSE = "iot/dh/response"  # platform -> device  {device_id, public_key, hmac_transcript}
TOPIC_DH_FINISH   = "iot/dh/finish"    # device -> platform  {device_id, hmac_transcript}

# Default key agreement algorithm for devices
DEFAULT_KA_ALGORITHM = "ecdh_ephemeral"  # or "auth_dh"