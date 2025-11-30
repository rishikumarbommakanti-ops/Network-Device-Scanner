#!/usr/bin/env python3
"""
Network Device Scanner & Monitoring Tool
Detect and track all devices on your network with MAC addresses, IPs, and device info
"""

import subprocess
import socket
import re
import csv
import json
from datetime import datetime
from pathlib import Path
import platform

class NetworkDeviceScanner:
    def __init__(self):
        self.devices = []
        self.oui_database = {}  # Manufacturer lookup
        self.device_map = {}  # For user mapping
        print("\n" + "="*70)
        print("🔍 NETWORK DEVICE SCANNER & MONITORING TOOL")
        print("="*70)
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        self.load_device_database()

    def load_device_database(self):
        """Load saved device database if exists"""
        if Path('device_database.json').exists():
            try:
                with open('device_database.json', 'r') as f:
                    self.device_map = json.load(f)
                print(f"✅ Loaded {len(self.device_map)} devices from database")
            except Exception as e:
                print(f"⚠️ Could not load database: {e}")

    def scan_arp_table(self):
        """Scan ARP table for devices on network"""
        print("\n[1/3] Scanning ARP table for connected devices...")
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True,
                    shell=True
                )
            else:  # Linux/Mac
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True
                )
            
            # Parse ARP output
            for line in result.stdout.split('\n'):
                # Windows format: 192.168.x.x        XX-XX-XX-XX-XX-XX  dynamic
                # Linux format: ? (192.168.x.x) at XX:XX:XX:XX:XX:XX
                match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9A-Fa-f:-]{17})', line)
                if match:
                    ip_addr = match.group(1)
                    mac_addr = match.group(2).replace('-', ':').upper()
                    self.devices.append({
                        'ip': ip_addr,
                        'mac': mac_addr,
                        'hostname': self.get_hostname(ip_addr),
                        'manufacturer': self.get_manufacturer(mac_addr),
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'user': self.device_map.get(mac_addr, 'Unknown')
                    })
            
            print(f"✅ Found {len(self.devices)} devices on network")
            return self.devices
        except Exception as e:
            print(f"❌ Error scanning ARP table: {e}")
            return []

    def get_hostname(self, ip_addr):
        """Attempt to resolve IP to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
            return hostname
        except:
            return "Unknown"

    def get_manufacturer(self, mac_addr):
        """Get device manufacturer from MAC address prefix"""
        # This would typically query an OUI database
        # For now, return a generic identifier
        prefix = mac_addr[:8].replace(':', '')
        # You could integrate with an OUI database here
        return f"Device ({prefix})"

    def display_devices(self):
        """Display discovered devices"""
        print("\n" + "="*70)
        print("📊 DISCOVERED DEVICES")
        print("="*70 + "\n")
        
        if not self.devices:
            print("❌ No devices found on network")
            return
        
        for idx, device in enumerate(self.devices, 1):
            print(f"{idx}. {device['hostname']}")
            print(f"   IP Address: {device['ip']}")
            print(f"   MAC Address: {device['mac']}")
            print(f"   Manufacturer: {device['manufacturer']}")
            print(f"   User Assigned: {device['user']}")
            print(f"   First Seen: {device['first_seen']}")
            print()

    def export_to_csv(self, filename='devices.csv'):
        """Export device list to CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'ip', 'mac', 'hostname', 'manufacturer', 
                    'user', 'first_seen', 'last_seen'
                ])
                writer.writeheader()
                writer.writerows(self.devices)
            print(f"\n✅ Exported {len(self.devices)} devices to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {e}")

    def export_to_json(self, filename='devices.json'):
        """Export device list to JSON"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.devices, f, indent=2)
            print(f"\n✅ Exported {len(self.devices)} devices to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {e}")

    def map_device_user(self, mac_addr, user_email):
        """Map MAC address to user/email"""
        self.device_map[mac_addr] = user_email
        self.save_device_database()
        print(f"✅ Mapped {mac_addr} -> {user_email}")

    def save_device_database(self):
        """Save device mapping to database"""
        try:
            with open('device_database.json', 'w') as f:
                json.dump(self.device_map, f, indent=2)
        except Exception as e:
            print(f"⚠️ Could not save database: {e}")

    def run_scan(self):
        """Run complete network scan"""
        self.scan_arp_table()
        self.display_devices()
        
        # Auto-export
        self.export_to_csv()
        self.export_to_json()
        
        print("\n" + "="*70)
        print("✨ Network scan complete!")
        print("="*70)

if __name__ == "__main__":
    scanner = NetworkDeviceScanner()
    scanner.run_scan()
    
    # Example of mapping devices to users:
    # scanner.map_device_user('AA:BB:CC:DD:EE:FF', 'user@gmail.com')
