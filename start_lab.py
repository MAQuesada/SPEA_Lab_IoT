"""
Master orchestrator to launch the entire SPEA Lab IoT ecosystem.
Boots the gateway, dashboard, monitor, and multiple device terminals concurrently.
"""

import subprocess
import sys
import time
import os

# Ensure Python finds the 'src' folder
env = os.environ.copy()
env["PYTHONPATH"] = "src"

print("🚀 Building the SPEA Lab IoT ecosystem...")

# 1. Launch the IoT Platform (Gateway)
print("[1/7] Starting Platform...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.server"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)
time.sleep(2) # 2-second pause to ensure the platform loads first

# 2. Launch the Feed viewer (Monitor)
print("[2/7] Starting Feed Subscriber...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.feed_subscriber"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 3. Launch the Web Dashboard (Streamlit)
print("[3/7] Starting Streamlit Dashboard...")
subprocess.Popen(
    [sys.executable, "-m", "streamlit", "run", "src/spea_lab_iot/dashboard.py"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 4. Launch the Device (Keypad Mode with Auto-Discovery)
print("[4/7] Starting Sensor Keypad (Auto-Discovery)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_keypad"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 5. Launch the Device (Screen Mode with Automatic PIN)
print("[5/7] Starting Sensor Screen (Automatic PIN)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_screen"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 6. Launch the Device (No-UI Mode with static PIN and ID)
print("[6/7] Starting Sensor Screen (Automatic PIN)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_no_ui"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 6. Launch the Extra Device Menu Terminal
print("[7/7] Starting Extra Devices Menu...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_menu"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

print("\n✅ Ecosystem started successfully. Check the 7 windows.")
print("👉 Use the Web Dashboard (http://localhost:8501) to enroll devices.")