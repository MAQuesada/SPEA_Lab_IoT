import sys
from spea_lab_iot import device_keypad, device_screen, device_no_ui

def main():
    print("\n" + "=" * 50)
    print("🛠️  EXTRA DEVICES MENU")
    print("=" * 50)
    print("1. Launch as Keypad (You enter the PIN)")
    print("2. Launch as Screen (It generates the PIN)")
    print("Another thing - Close terminal")
    
    choice = input("Choose [1-2]: ").strip()
    
    if choice == "1":
        device_keypad.main()
    elif choice == "2":
        device_screen.main()
    else:
        print("Shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()