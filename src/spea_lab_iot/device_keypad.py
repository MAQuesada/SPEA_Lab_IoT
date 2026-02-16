"""
Device with keypad UI: user enters the platform PIN to pair, then device sends data.
"""

from dotenv import load_dotenv

load_dotenv()

from spea_lab_iot.device import run_device

SENSOR_ID = "sensor-keypad-01"


def main() -> None:
    run_device(sensor_id=SENSOR_ID, ui_mode="keypad", pin=None, alg=None)


if __name__ == "__main__":
    main()
