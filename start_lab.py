import subprocess
import sys
import time
import os
import random

# Aseguramos que Python encuentre la carpeta 'src'
env = os.environ.copy()
env["PYTHONPATH"] = "src"

print("🚀 Levantando el ecosistema SPEA Lab IoT...")

# 1. Levantar la Plataforma IoT
print("[1/5] Iniciando Plataforma...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.server"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)
time.sleep(2) # Pausa de 2s para asegurar que la plataforma cargue primero

# 2. Levantar el visualizador de Feed
print("[2/5] Iniciando Feed Subscriber...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.feed_subscriber"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 3. Levantar el Dashboard Web (Streamlit)
print("[3/5] Iniciando Dashboard de Streamlit...")
subprocess.Popen(
    [sys.executable, "-m", "streamlit", "run", "src/spea_lab_iot/dashboard.py"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 4. Levantar el Dispositivo (Modo Keypad)
print("[4/5] Iniciando Sensor 01 (Keypad)...")
device_keypad_cmd = "import sys; sys.path.insert(0, 'src'); from spea_lab_iot.device import run_device; run_device('sensor-01', 'keypad')"
subprocess.Popen(
    [sys.executable, "-c", device_keypad_cmd], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 5. Levantar el Dispositivo (Modo Screen)
print("[5/5] Iniciando Sensor Screen 01...")
# Generamos el PIN aleatorio y elegimos los algoritmos aquí, tal como lo haría el hardware
screen_pin = str(random.randint(100000, 999999))
alg = "AES-GCM"
ka = "ecdh_ephemeral"

device_screen_cmd = f"import sys; sys.path.insert(0, 'src'); from spea_lab_iot.device import run_device; run_device('sensor-screen-01', 'screen', pin='{screen_pin}', alg='{alg}', ka_algorithm='{ka}')"
subprocess.Popen(
    [sys.executable, "-c", device_screen_cmd], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

print("✅ Ecosistema iniciado. Revisa las 5 ventanas.")