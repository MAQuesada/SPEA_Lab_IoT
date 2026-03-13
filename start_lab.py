import subprocess
import sys
import time
import os

# Aseguramos que Python encuentre la carpeta 'src'
env = os.environ.copy()
env["PYTHONPATH"] = "src"

print("🚀 Levantando el ecosistema SPEA Lab IoT...")

# 1. Levantar la Plataforma IoT (Gateway)
print("[1/5] Iniciando Plataforma...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.server"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)
time.sleep(2) # Pausa de 2s para asegurar que la plataforma cargue primero

# 2. Levantar el visualizador de Feed (Monitor)
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

# 4. Levantar el Dispositivo (Modo Keypad Autodescubrimiento)
print("[4/5] Iniciando Sensor Keypad (Auto-Descubrimiento)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_keypad"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 5. Levantar el Dispositivo (Modo Screen Automático)
print("[5/5] Iniciando Sensor Screen (PIN Automático)...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_screen"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

# 6. Levantar la Terminal de Menú Extra
print("[6/6] Iniciando Menú de Dispositivos Extra...")
subprocess.Popen(
    [sys.executable, "-m", "spea_lab_iot.device_menu"], 
    env=env, 
    creationflags=subprocess.CREATE_NEW_CONSOLE
)

print("\n✅ Ecosistema iniciado correctamente. Revisa las 6 ventanas.")
print("👉 Usa el Dashboard Web (http://localhost:8501) para enrolar los dispositivos.")