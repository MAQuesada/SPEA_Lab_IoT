"""
Motor principal del dispositivo IoT.
(UI separada en device_keypad.py y device_screen.py).
Gestiona la conexión MQTT, la criptografía (R4, R5) y la resiliencia (R2, R3).
"""

import base64
import json
import random
import signal
import sys
import threading
import time

import paho.mqtt.client as mqtt

from spea_lab_iot.config import (
    MQTT_BROKER_HOST,
    MQTT_BROKER_PORT,
    MQTT_PASSWORD,
    MQTT_USER,
    TOPIC_DATA,
    TOPIC_ENROLL,
    TOPIC_ENROLL_RESPONSE,
    TOPIC_REKEY,
    TOPIC_REKEY_RESPONSE,
    TOPIC_ADMIN_REMOVE,
)
from spea_lab_iot.key_manager import KeyManager
from spea_lab_iot.dh_device import run_dh_handshake
from spea_lab_iot.dh_device import run_dh_handshake

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import pad

# Sensor simulation (baseline + deviation)
BASELINE_TEMPERATURE_C = 24.0
BASELINE_HUMIDITY_PCT = 55.0
TEMPERATURE_DEVIATION = 10.0
HUMIDITY_DEVIATION = 10.0
TEMP_MIN = 0.0
TEMP_MAX = 50.0
HUMIDITY_MIN = 0.0
HUMIDITY_MAX = 100.0
DATA_INTERVAL_SEC = 5
PAIRING_RETRY_SEC = 3
ENROLL_WAIT_TIMEOUT_SEC = 30

POS_ALG = ["AES-CBC", "AES-GCM"]
POS_DH = ["ecdh_ephemeral", "auth_dh"]

def _read_temperature() -> float:
    value = BASELINE_TEMPERATURE_C + random.uniform(-TEMPERATURE_DEVIATION, TEMPERATURE_DEVIATION)
    return round(max(TEMP_MIN, min(TEMP_MAX, value)), 1)

def _read_humidity() -> float:
    value = BASELINE_HUMIDITY_PCT + random.uniform(-HUMIDITY_DEVIATION, HUMIDITY_DEVIATION)
    return round(max(HUMIDITY_MIN, min(HUMIDITY_MAX, value)), 1)

def encrypt_aead_aes_gcm(key: bytes, plaintext: bytes, aad: bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag

def encrypt_aes_cbc_hmac(enc_key: bytes, mac_key: bytes, plaintext: bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    tag = h.digest()
    return iv, ciphertext, tag

def run_device(
    sensor_id: str,
    ui_mode: str,
    pin: str | None = None,
    pin: str | None = None,
    alg: str | None = None,
    ka_algorithm: str | None = None,
    ka_algorithm: str | None = None,
) -> None:
    
    running_global = True

    def stop_global(_: int, __: object | None) -> None:
        nonlocal running_global
        running_global = False

    signal.signal(signal.SIGINT, stop_global)

    while running_global:
        current_pin = pin
        current_alg = alg
        current_ka = ka_algorithm

        # 1. GESTIÓN DE CREDENCIALES
        if ui_mode == "keypad":
            # El lanzador ya nos pasa los datos. Si faltan, es que nos han revocado.
            if not current_pin or not current_alg or not current_ka:
                print(f"\n🔌 [{sensor_id}] Conexión finalizada permanentemente.")
                print("👉 Vuelve a ejecutar la terminal del Keypad para iniciar otra sesión.")
                break
                
        elif ui_mode == "screen":
            # Si no hay credenciales (inicio o revocación), el motor auto-genera el PIN
            if not current_pin or not current_alg or not current_ka:
                print("\n🔄 Generando nuevo PIN de conexión seguro...")
                current_pin = str(random.randint(100000, 999999))
                current_alg = random.choice(POS_ALG)
                current_ka = random.choice(POS_DH)
                
            print(f"\n=================================")
            print(f"📱 MODO SCREEN - ID: {sensor_id}")
            print(f"🔑 NUEVO PIN: {current_pin}")
            print(f"🔒 Algoritmo Cifrado: {current_alg}")
            print(f"=================================")
            print("⏳ Intentando conectar con la Plataforma ...")

        key_mgr = KeyManager(sensor_id)
        key_mgr.load_keys() 
        key_mgr.derive_master_key(current_pin)

        enrolled_event = threading.Event()
        revoked_event = threading.Event() 
        data_topic_ref: list[str | None] = [None]

        def on_connect(client, userdata, flags, reason_code, properties=None):
            if reason_code == 0:
                client.subscribe(TOPIC_ENROLL_RESPONSE, qos=1)
                client.subscribe(TOPIC_REKEY_RESPONSE, qos=1)
                client.subscribe(TOPIC_ADMIN_REMOVE, qos=1) 

        def on_message(client, userdata, msg):
            if msg.topic == TOPIC_ADMIN_REMOVE:
                try:
                    payload = json.loads(msg.payload.decode())
                    if payload.get("device_id") == sensor_id:
                        print("\n[!] ALERTA: La plataforma ha eliminado este dispositivo.")
                        revoked_event.set()
                except Exception:
                    pass
                return

            if msg.topic == TOPIC_REKEY_RESPONSE:
                try:
                    payload = json.loads(msg.payload.decode())
                    if payload.get("device_id") != sensor_id: return
                    nonce = base64.b64decode(payload["nonce"])
                    tag = base64.b64decode(payload["tag"])
                    ciphertext = base64.b64decode(payload["ciphertext"])
                    key_id = payload["key_id"]
                    cipher = AES.new(key_mgr.master_key, AES.MODE_GCM, nonce=nonce)
                    new_session_key = cipher.decrypt_and_verify(ciphertext, tag)
                    key_mgr.set_session_key(new_session_key, key_id)
                    print(f"✅ Key rotation successful. New Key ID: {key_id}")
                except Exception as e:
                    print(f"Error handling rekey response: {e}")
                return

            if msg.topic == TOPIC_ENROLL_RESPONSE:
                try:
                    payload = json.loads(msg.payload.decode())
                    if payload.get("device_id") == sensor_id and payload.get("status") == "enrolled":
                        data_topic_ref[0] = payload.get("data_topic", TOPIC_DATA)
                        enrolled_event.set()
                except Exception:
                    pass

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
        client.on_connect = on_connect
        client.on_message = on_message

        try:
            client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=60)
        except Exception as e:
            print(f"Could not connect: {e}", file=sys.stderr)
            sys.exit(1)

        client.loop_start()

        def send_pairing() -> None:
            payload = json.dumps({"action": "pairing", "device_id": sensor_id, "pin": current_pin, "alg": current_alg})
            client.publish(TOPIC_ENROLL, payload, qos=1)

        # 2. PROCESO DE ENROLAMIENTO
        if ui_mode == "keypad":
            send_pairing()
            if not enrolled_event.wait(timeout=5):
                print("\n❌ ERROR: Acceso denegado o credenciales inválidas.")
                print("👉 Verifica los datos en el Dashboard Web e inténtalo de nuevo.\n")
                client.loop_stop()
                client.disconnect()
                pin, alg, ka_algorithm = None, None, None
                continue
        else:
            while not enrolled_event.is_set() and running_global and not revoked_event.is_set():
                send_pairing()
                enrolled_event.wait(timeout=PAIRING_RETRY_SEC)

        if not running_global or revoked_event.is_set():
            client.loop_stop()
            client.disconnect()
            pin, alg, ka_algorithm = None, None, None
            continue

       
        # 3. INTERCAMBIO DE CLAVES Y ENVÍO DE DATOS
        print(f"Enrolled. Starting DH key agreement (algorithm={current_ka})...")
        try:
            session_key, auth_key = run_dh_handshake(
                client=client, device_id=sensor_id, pin=current_pin, algorithm=current_ka
            )
        except RuntimeError as e:
            print(f"Key agreement failed: {e}", file=sys.stderr)
            client.loop_stop()
            client.disconnect()
            pin, alg, ka_algorithm = None, None, None
            continue

        key_mgr.set_session_key(session_key, key_id=0)
        
        data_topic = data_topic_ref[0] or TOPIC_DATA
        print(f"Publishing data to {data_topic} (Ctrl+C to stop)")

        rekey_attempts = 0  # Contador de intentos para la resiliencia

        while running_global and not revoked_event.is_set():
            
            # --- ZONA DE ROTACIÓN DE CLAVES ---
            if key_mgr.check_rotation_needed():
                if rekey_attempts >= 3:
                    print("\n[!] ALERTA: La plataforma no responde.")
                    print("Asumiendo que el dispositivo ha sido ELIMINADO de la red.")
                    revoked_event.set()
                    continue

                timestamp = str(int(time.time()))
                payload_dict = {"device_id": sensor_id, "ts": timestamp}
                h = HMAC.new(key_mgr.master_key, digestmod=SHA256)
                h.update(json.dumps(payload_dict, sort_keys=True).encode())
                payload_dict["sig"] = base64.b64encode(h.digest()).decode()

                client.publish(TOPIC_REKEY, json.dumps(payload_dict), qos=1)
                print(f"🔄 Invoked key rotation... (Intento {rekey_attempts + 1}/3)")
                rekey_attempts += 1
                
                # Esperamos 5 segundos a que la plataforma responda antes de intentar de nuevo
                for _ in range(5):
                    if revoked_event.is_set(): break
                    time.sleep(1)
                continue
                
            # Si llegamos aquí, no necesitamos rotar o la rotación fue exitosa
            rekey_attempts = 0

            # --- ZONA DE ENVÍO DE DATOS ---
            temperature = _read_temperature()
            humidity = _read_humidity()
            payload = {
                "device_id": sensor_id, "temperature": temperature,
                "humidity": humidity, "unit_temp": "celsius", "unit_humidity": "%",
            }

            plaintext = json.dumps(payload).encode()
            timestamp = str(int(time.time()))
            aad = (sensor_id + "|" + timestamp).encode()

            try:
                session_key_bytes, key_id = key_mgr.get_session_key()

                if current_alg == "AES-CBC":
                    enc_key = session_key_bytes[:16]
                    auth_key = session_key_bytes[16:]
                    nonce, ciphertext, tag = encrypt_aes_cbc_hmac(enc_key, auth_key, plaintext)
                elif current_alg == "AES-GCM":
                    nonce, ciphertext, tag = encrypt_aead_aes_gcm(session_key_bytes, plaintext, aad)

                encrypted_payload = {
                    "device_id": sensor_id, "key_id": key_id, "nonce": base64.b64encode(nonce).decode(),
                    "ciphertext": base64.b64encode(ciphertext).decode(), "tag": base64.b64encode(tag).decode(),
                    "alg": current_alg, "ts": timestamp,
                }

                client.publish(data_topic, json.dumps(encrypted_payload), qos=1)
                print(f"Published: device_id={sensor_id!r}, temp={temperature}°C, humidity={humidity}%")

            except ValueError as e:
                print(f"Waiting for key... ({e})")

            # Pausa entre envíos de datos
            for _ in range(DATA_INTERVAL_SEC):
                if revoked_event.is_set() or not running_global: break
                time.sleep(1)

        client.loop_stop()
        client.disconnect()

       # SI FUE ELIMINADO POR LA WEB O POR TIMEOUT
        if revoked_event.is_set():
            print("\n===========================================")
            print("🔌 CONEXIÓN CERRADA POR LA PLATAFORMA.")
            print("===========================================\n")
            break # <--- Salimos del motor y le devolvemos el control al lanzador

    print("Device stopped.")