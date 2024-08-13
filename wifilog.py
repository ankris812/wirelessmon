import os
from scapy.all import *

def enable_monitor_mode(interface):
    print(f"Enabling monitor mode on {interface}...")
    os.system(f"airmon-ng start {interface}")
    return interface + "mon"

def disable_monitor_mode(interface):
    print(f"Disabling monitor mode on {interface}...")
    os.system(f"airmon-ng stop {interface}")

def scan_wifi_networks(interface):
    networks = {}
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet.info.decode('utf-8')
            bssid = packet.addr2
            if ssid not in networks:
                networks[ssid] = bssid

    print("Scanning for WiFi networks...")
    sniff(iface=interface, prn=packet_handler, timeout=10)
    return networks

def display_networks(networks):
    print("\nAvailable WiFi Networks:")
    for i, (ssid, bssid) in enumerate(networks.items(), 1):
        print(f"{i}. SSID: {ssid}, BSSID: {bssid}")

def scan_clients(interface, target_bssid):
    clients = set()
    def packet_handler(packet):
        if packet.haslayer(Dot11) and packet.addr2 and packet.addr1:
            if packet.addr1 == target_bssid or packet.addr2 == target_bssid:
                clients.add(packet.addr2 if packet.addr1 == target_bssid else packet.addr1)

    print(f"\nScanning for clients connected to BSSID: {target_bssid}...")
    sniff(iface=interface, prn=packet_handler, timeout=20)
    return clients

def main():
    original_interface = input("Please enter the network interface (e.g., wlan0): ")
    
    monitor_interface = enable_monitor_mode(original_interface)
    
    try:
        networks = scan_wifi_networks(monitor_interface)
        if not networks:
            print("No networks found.")
            return
        
        display_networks(networks)

        choice = int(input("\nEnter the number of the network you want to monitor: "))
        selected_ssid, selected_bssid = list(networks.items())[choice - 1]
        print(f"\nSelected Network: SSID: {selected_ssid}, BSSID: {selected_bssid}")

        clients = scan_clients(monitor_interface, selected_bssid)
        if not clients:
            print("No clients found.")
        else:
            print("\nConnected devices (MAC Addresses):")
            for client in clients:
                print(client)
        
        with open("wifi-mac.txt", "w") as file:
            file.write(f"SSID: {selected_ssid}, BSSID: {selected_bssid}\n")
            file.write("Connected devices (MAC Addresses):\n")
            for client in clients:
                file.write(f"{client}\n")
        print("\nMAC addresses have been saved to wifi-mac.txt.")
    
    finally:
        disable_monitor_mode(monitor_interface)

if __name__ == "__main__":
    # Ensure the script is run with superuser privileges
    if os.geteuid() != 0:
        print("This script must be run as root!")
    else:
        main()
