"""Configuration from environment variables and topic names."""

import os
from dotenv import load_dotenv

load_dotenv()

#=================MQTT===================================
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "public.cloud.shiftr.io")
MQTT_BROKER_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "public")
MQTT_PASSWORD = os.environ.get("MQTT_PASSWORD", "public")

#====================TOPICS==============================
# Topics enroll
TOPIC_ENROLL = "iot/enroll"
TOPIC_ENROLL_RESPONSE = "iot/enroll/response"

# Topics for data
TOPIC_DATA = "iot/data"
TOPIC_FEED = "iot/feed"

# Topics to renovate key
TOPIC_REKEY = "iot/rekey"
TOPIC_REKEY_RESPONSE = "iot/rekey/response"

# Topics for DH
TOPIC_DH_INIT = "iot/dh/init"
TOPIC_DH_RESPONSE = "iot/dh/response"
TOPIC_DH_FINISH = "iot/dh/finish"

# --- ADMIN TOPICS PARA EL DASHBOARD WEB ---
TOPIC_ADMIN_BASE = "iot/admin/#"
TOPIC_ADMIN_REQ_DEVICES = "iot/admin/req_devices"
TOPIC_ADMIN_RES_DEVICES = "iot/admin/res_devices"
TOPIC_ADMIN_REMOVE = "iot/admin/remove"
TOPIC_ADMIN_ADD = "iot/admin/add"

#============================OTHER VARIABLES===============================
# Platform: default PIN for keypad devices (cannot be deleted)
PLATFORM_DEFAULT_PIN = os.environ.get("PLATFORM_DEFAULT_PIN", "platform-pin")

# Default key agreement algorithm for devices
DEFAULT_KA_ALGORITHM = "ecdh_ephemeral"  # or "auth_dh"

# Salt for some generated keys
SALT_AUTH = b"spea-lab-iot-auth"
SALT_SESS = b"spea-lab-iot-session"
SALT_KM = b"iot-mock-salt"

KEY_ROTATION_INTERVAL_SEC = os.environ.get("KEY_ROTATION_INTERVAL_SEC", "60")
KEY_ROTATION_MSG_LIMIT = os.environ.get("KEY_ROTATION_MSG_LIMIT", "100")

PLATFORM_LOG = os.environ.get("PLATFORM_LOG", "") # It can be yes, true, 1 as a string