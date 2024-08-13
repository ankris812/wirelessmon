import os
from scapy.all import *

def load_mac_addresses(filename):
    mac_addresses = set()
    with open(filename, "r") as file:
        for line in file:
            if "MAC:" in line:
                mac = line.split("MAC:")[1].strip()
                mac_addresses.add(mac)
    return mac_addresses

def scan_connected_devices(interface, mac_addresses):
    def packet_handler(packet):
        # Filtrar solo paquetes de respuesta ARP (gratuita o no)
        if packet.haslayer(ARP) and packet.op in (1, 2):  # ARP request or reply
            mac = packet.hwsrc  # Dirección MAC del dispositivo
            if mac in mac_addresses:
                print(f"ALERT: Detected known device MAC: {mac} on network.")

    print("Monitoring connected devices on all nearby networks... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_handler, store=0)

def main():
    # Load MAC addresses from wifi-mac.txt
    mac_addresses = load_mac_addresses("wifi-mac.txt")
    
    if not mac_addresses:
        print("No MAC addresses found in wifi-mac.txt.")
        return

    # Ask for the interface to monitor
    interface = input("Please enter the network interface (e.g., wlan0): ")
    
    try:
        scan_connected_devices(interface, mac_addresses)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

if __name__ == "__main__":
    # Ensure the script is run with superuser privileges
    if os.geteuid() != 0:
        print("This script must be run as root!")
    else:
        main()
