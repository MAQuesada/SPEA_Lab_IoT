
import sys
import os

# Add src to python path if needed (though running from src root should work)
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from spea_lab_iot.device import run_device

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python run_device_wrapper.py <sensor_id> <mode> <pin> <alg>")
        sys.exit(1)
    
    # sensor_id, mode, pin, alg
    run_device(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
