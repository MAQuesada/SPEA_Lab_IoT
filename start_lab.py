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

print("🚀 Levantando el ecosistema SPEA Lab IoT...")

# 1. Launch the IoT Platform (Gateway)
print("[1/6] Iniciando Plataforma...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.server"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)
time.sleep(2) # 2-second pause to ensure the platform loads first

# 2. Launch the Feed viewer (Monitor)
print("[2/6] Iniciando Feed Subscriber...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.feed_subscriber"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 3. Launch the Web Dashboard (Streamlit)
print("[3/6] Iniciando Dashboard de Streamlit...")
subprocess.Popen(
    [sys.executable, "-m", "streamlit", "run", "src/spea_lab_iot/dashboard.py"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 4. Launch the Device (Keypad Mode with Auto-Discovery)
print("[4/6] Iniciando Sensor Keypad (Auto-Descubrimiento)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_keypad"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 5. Launch the Device (Screen Mode with Automatic PIN)
print("[5/6] Iniciando Sensor Screen (PIN Automático)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_screen"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 6. Launch the Extra Device Menu Terminal
print("[6/6] Iniciando Menú de Dispositivos Extra...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_menu"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

print("\n✅ Ecosistema iniciado correctamente. Revisa las 6 ventanas.")
print("👉 Usa el Dashboard Web (http://localhost:8501) para enrolar los dispositivos.")