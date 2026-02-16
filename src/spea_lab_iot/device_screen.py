"""
Device with screen UI: displays device ID and a random 6-digit PIN, retries pairing until enrolled, then sends data.

On startup the script generates a random 6-digit PIN, prints it, and uses it for pairing. The admin must add that device_id + PIN on the platform via "Add device" before the device can pair.
"""

import random

from dotenv import load_dotenv

load_dotenv()

from spea_lab_iot.device import run_device

SENSOR_ID = "sensor-screen-01"
POS_ALG = ["AES-CBC", "AES-GCM"]


def main() -> None:
    pin = str(random.randint(100000, 999999))
    alg = random.choice(POS_ALG)
    run_device(sensor_id=SENSOR_ID, ui_mode="screen", pin=pin, alg=alg)


if __name__ == "__main__":
    main()
