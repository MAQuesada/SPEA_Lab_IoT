"""
Launcher for the device in Keypad mode.
Auto-discovers its Device ID and Algorithm by searching for the PIN on the platform.
Runs in an infinite loop so the terminal stays active upon revocation.
"""

import sys, time, json
import paho.mqtt.client as mqtt
from spea_lab_iot.device import run_device
from spea_lab_iot.config import (MQTT_BROKER_HOST, MQTT_BROKER_PORT, MQTT_USER, MQTT_PASSWORD, TOPIC_ADMIN_REQ_DEVICES, TOPIC_ADMIN_RES_DEVICES)

def main() -> None:
    while True:
        print("\n" + "=" * 55)
        print("🎛️  KEYPAD MODE (Auto-Discovery by PIN)")
        print("=" * 55)
        
        target_pin = input("🔑 Enter the PIN you registered (or press Enter to exit): ").strip()
        if not target_pin:
            sys.exit(0)

        print("🔍 Consulting the platform...")
        found_id, found_alg = None, None

        def on_connect(client, userdata, flags, rc, properties=None):
            if rc == 0:
                client.subscribe(TOPIC_ADMIN_RES_DEVICES)
                client.publish(TOPIC_ADMIN_REQ_DEVICES, "get")

        def on_message(client, userdata, msg):
            nonlocal found_id, found_alg
            if msg.topic == TOPIC_ADMIN_RES_DEVICES:
                try:
                    devices = json.loads(msg.payload.decode())
                    for did, info in devices.items():
                        if info.get("pin") == target_pin:
                            found_id, found_alg = did, info.get("alg")
                            break
                except Exception: pass
                finally: client.disconnect()

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
        client.on_connect, client.on_message = on_connect, on_message
        
        try: client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, 60)
        except Exception as e: print(f"❌ Error: {e}"); time.sleep(2); continue
            
        start_time = time.time()
        while found_id is None and time.time() - start_time < 5: client.loop(0.1)
            
        if not found_id:
            print(f"❌ The platform does not recognize the PIN '{target_pin}'. Try again.")
            time.sleep(1)
            continue
            
        print(f"✅ Success! You are: {found_id} with {found_alg}")
        ka_alg = input("🤝 Choose DH ('ecdh_ephemeral' or 'auth_dh') [ecdh_ephemeral]: ").strip() or "ecdh_ephemeral"

        # Call the engine. If revoked by the platform, the engine breaks and the loop restarts here
        run_device(sensor_id=found_id, ui_mode="keypad", pin=target_pin, alg=found_alg, ka_algorithm=ka_alg)
        time.sleep(1)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)