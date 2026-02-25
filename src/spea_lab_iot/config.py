"""Configuration from environment variables and topic names."""

import os

from dotenv import load_dotenv

load_dotenv()

MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "public.cloud.shiftr.io")
MQTT_BROKER_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "public")
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD", "public")

# Topics (R1)
TOPIC_ENROLL          = "iot/enroll"
TOPIC_ENROLL_RESPONSE = "iot/enroll/response"
TOPIC_DATA            = "iot/data"
TOPIC_FEED            = "iot/feed"

# Topics (R2-R3)
TOPIC_REKEY          = "iot/rekey"
TOPIC_REKEY_RESPONSE = "iot/rekey/response"

# Topics (R4)
TOPIC_DH_INIT     = "iot/dh/init"
TOPIC_DH_RESPONSE = "iot/dh/response"
TOPIC_DH_FINISH   = "iot/dh/finish"

# Platform: default PIN for keypad devices (cannot be deleted)
PLATFORM_DEFAULT_PIN = os.environ.get("PLATFORM_DEFAULT_PIN", "platform-pin")

# Default key agreement algorithm for devices
DEFAULT_KA_ALGORITHM = "ecdh_ephemeral"  # or "auth_dh"