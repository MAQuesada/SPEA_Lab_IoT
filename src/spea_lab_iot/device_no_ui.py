import sys, random, time
from spea_lab_iot.device import run_device
from spea_lab_iot.config import PLATFORM_DEFAULT_PIN, DEFAULT_KA_ALGORITHM

ID = "default-sensor"
PIN = PLATFORM_DEFAULT_PIN
ALG = "AES-CBC"
DH = DEFAULT_KA_ALGORITHM


def main() -> None:
    run_device(sensor_id=ID, ui_mode=None, pin=PIN, alg=ALG, ka_algorithm=DH)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
