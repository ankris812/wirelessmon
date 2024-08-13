import bluetooth
from scapy.all import *
import requests
import time

def get_manufacturer(mac):
    # OUI API to get the manufacturer from MAC
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        return response.text
    except:
        return "Unknown"

def scan_bluetooth_devices():
    print("Scanning for Bluetooth devices...")
    devices = bluetooth.discover_devices(lookup_names=True, lookup_class=False)
    return devices

def main():
    seen_devices = set()

    print("Monitoring Bluetooth devices. Press Ctrl+C to stop.")
    
    try:
        with open("ble-mac.txt", "w") as file:
            file.write("Nearby Bluetooth devices (MAC Addresses and Manufacturers):\n")
            
            while True:
                devices = scan_bluetooth_devices()
                
                for addr, name in devices:
                    if addr not in seen_devices:  # Avoid duplicate entries
                        manufacturer = get_manufacturer(addr)
                        print(f"Device: {name}, MAC: {addr}, Manufacturer: {manufacturer}")
                        file.write(f"Device: {name}, MAC: {addr}, Manufacturer: {manufacturer}\n")
                        file.flush()  # Ensure data is written to the file immediately
                        seen_devices.add(addr)
                
                time.sleep(10)  # Wait for 10 seconds before scanning again

    except KeyboardInterrupt:
        print("\nMonitoring stopped. Device information saved to ble-mac.txt.")

if __name__ == "__main__":
    main()
