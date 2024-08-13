import bluetooth
import time

def load_mac_addresses(filename):
    mac_addresses = set()
    with open(filename, "r") as file:
        for line in file:
            if "MAC:" in line:
                mac = line.split("MAC:")[1].strip()
                mac_addresses.add(mac)
    return mac_addresses

def scan_bluetooth_devices(mac_addresses):
    print("Monitoring Bluetooth devices... Press Ctrl+C to stop.")
    try:
        while True:
            devices = bluetooth.discover_devices(lookup_names=True)
            for addr, name in devices:
                if addr in mac_addresses:
                    print(f"ALERT: Detected known Bluetooth device MAC: {addr}, Name: {name}")
            time.sleep(10)  # Espera 10 segundos antes de escanear nuevamente

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

def main():
    # Load MAC addresses from ble-mac.txt
    mac_addresses = load_mac_addresses("ble-mac.txt")
    
    if not mac_addresses:
        print("No MAC addresses found in ble-mac.txt.")
        return

    scan_bluetooth_devices(mac_addresses)

if __name__ == "__main__":
    main()
