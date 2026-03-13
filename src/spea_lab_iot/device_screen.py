import sys, random, time
from spea_lab_iot.device import run_device

def main() -> None:
    while True:
        print("\n" + "=" * 55)
        print("📺 MODO SCREEN (Auto-Generación de Credenciales)")
        print("=" * 55)
        
        screen_id = f"sensor-screen-{random.randint(10, 99)}"
        
        run_device(sensor_id=screen_id, ui_mode="screen")
        time.sleep(2)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)