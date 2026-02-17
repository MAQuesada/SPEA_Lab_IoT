
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from spea_lab_iot.platform import run_platform

if __name__ == "__main__":
    # interactive=False for testing
    run_platform(interactive=False)
