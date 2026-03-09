"""
Device entry point: interactive menu to choose the device mode and run it.

Replaces device_keypad.py and device_screen.py as a single unified entry point.

Modes:
  1. Keypad  — user types the platform PIN and chooses an algorithm.
  2. Screen  — device generates a random PIN and algorithm, displays them,
               and retries pairing until the admin adds it on the platform.
"""

import random
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv

load_dotenv()

from spea_lab_iot.device import run_device

POS_ALG = ["AES-CBC", "AES-GCM"]
POS_DH = ["ecdh_ephemeral", "auth_dh"]

DEVICE_OPTIONS = [
    {
        "label": "Keypad device (sensor-keypad-01) — you enter the platform PIN and algorithm",
        "sensor_id": "sensor-keypad-01",
        "mode": "keypad",
        "pin": None,  # Will be prompted interactively inside run_device
        "alg": None,  # Will be prompted interactively inside run_device
        "dh": None,  # Will be prompted interactively inside run_device
    },
    {
        "label": "Screen device (sensor-screen-01) — random PIN and algorithm, retries until enrolled",
        "sensor_id": "sensor-screen-01",
        "mode": "screen",
        "pin": str(random.randint(100000, 999999)),
        "alg": random.choice(POS_ALG),
        "dh": random.choice(POS_DH),
    },
]


def main() -> None:
    print("=== Device Launcher ===")
    print("Select a device to start:\n")
    for i, opt in enumerate(DEVICE_OPTIONS, start=1):
        print(f"  {i}. {opt['label']}")
    print()

    while True:
        choice = input(f"Choice [1-{len(DEVICE_OPTIONS)}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(DEVICE_OPTIONS):
            break
        print(
            f"  Invalid choice. Please enter a number between 1 and {len(DEVICE_OPTIONS)}."
        )

    selected = DEVICE_OPTIONS[int(choice) - 1]

    print(f"\nStarting: {selected['label']}")
    if selected["mode"] == "screen":
        print(f"  Device ID : {selected['sensor_id']}")
        print(f"  PIN       : {selected['pin']}")
        print(f"  Algorithm : {selected['alg']}")
        print(f"  Exchange algorithm : {selected['dh']}")
        print("  Add this device on the platform before it can pair.\n")

    run_device(
        sensor_id=selected["sensor_id"],
        ui_mode=selected["mode"],
        pin=selected["pin"],
        alg=selected["alg"],
        ka_algorithm=selected["dh"],
    )


if __name__ == "__main__":
    main()
