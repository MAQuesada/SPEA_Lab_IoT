import sys
from spea_lab_iot import device_keypad, device_screen

def main():
    print("\n" + "=" * 50)
    print("🛠️  MENÚ DE DISPOSITIVOS EXTRA")
    print("=" * 50)
    print("1. Lanzar como Keypad (Tú pones el PIN)")
    print("2. Lanzar como Screen (Él genera el PIN)")
    print("3. Cerrar terminal")
    
    choice = input("Elige [1-3]: ").strip()
    
    if choice == "1":
        device_keypad.main()
    elif choice == "2":
        device_screen.main()
    else:
        print("Saliendo...")
        sys.exit(0)

if __name__ == "__main__":
    main()