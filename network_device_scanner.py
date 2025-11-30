#!/usr/bin/env python3
"""
Network Device Scanner & Monitoring Tool - ENHANCED
Detect and track all devices on your network with MAC addresses, IPs, device names, and connection duration
"""
import subprocess
import socket
import re
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
import platform

class NetworkDeviceScanner:
    def __init__(self):
        self.devices = []
        self.oui_database = {} # Manufacturer lookup
        self.device_map = {} # For user mapping
        self.device_history = {} # For tracking device connection history
        print("\n" + "="*70)
        print("🔍 NETWORK DEVICE SCANNER & MONITORING TOOL (ENHANCED)")
        print("="*70)
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        self.load_device_database()
        self.load_device_history()

    def load_device_database(self):
        """Load saved device database if exists"""
        if Path('device_database.json').exists():
            try:
                with open('device_database.json', 'r') as f:
                    self.device_map = json.load(f)
                print(f"✅ Loaded {len(self.device_map)} devices from database")
            except Exception as e:
                print(f"⚠️ Could not load database: {e}")

    def load_device_history(self):
        """Load device connection history"""
        if Path('device_history.json').exists():
            try:
                with open('device_history.json', 'r') as f:
                    self.device_history = json.load(f)
            except Exception as e:
                print(f"⚠️ Could not load history: {e}")

    def calculate_days_connected(self, first_seen_str):
        """Calculate days since device was first seen"""
        try:
            first_seen = datetime.fromisoformat(first_seen_str)
            days_connected = (datetime.now() - first_seen).days
            return days_connected
        except:
            return 0

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
                    
                    # Check if device was seen before
                    first_seen = self.device_history.get(mac_addr, datetime.now().isoformat())
                    
                    self.devices.append({
                        'ip': ip_addr,
                        'mac': mac_addr,
                        'hostname': self.get_hostname_advanced(ip_addr, mac_addr),
                        'manufacturer': self.get_manufacturer(mac_addr),
                        'first_seen': first_seen,
                        'last_seen': datetime.now().isoformat(),
                        'days_connected': self.calculate_days_connected(first_seen),
                        'user': self.device_map.get(mac_addr, 'Unknown')
                    })
                    
                    # Update history
                    if mac_addr not in self.device_history:
                        self.device_history[mac_addr] = first_seen
            
            print(f"✅ Found {len(self.devices)} devices on network")
            self.save_device_history()
            return self.devices
        except Exception as e:
            print(f"❌ Error scanning ARP table: {e}")
            return []

    def get_hostname_advanced(self, ip_addr, mac_addr):
        """Attempt to resolve IP to hostname using multiple methods"""
        # Method 1: Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
            if hostname and hostname != ip_addr:
                return hostname
        except:
            pass
        
        # Method 2: Check if we have stored hostname
        stored_name = self.device_map.get(mac_addr)
        if stored_name and '@' not in stored_name:  # If it's not an email
            return stored_name
        
        # Method 3: Try nbtstat on Windows (for NetBIOS names)
        if platform.system() == "Windows":
            try:
                result = subprocess.run(
                    ['nbtstat', '-a', ip_addr],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                # Extract hostname from nbtstat output
                for line in result.stdout.split('\n'):
                    if '<20>' in line or '<00>' in line:
                        parts = line.split()
                        if parts:
                            hostname = parts[0].strip()
                            if hostname and hostname != ip_addr:
                                return hostname
            except:
                pass
        
        # Method 4: Try getfqdn
        try:
            hostname = socket.getfqdn(ip_addr)
            if hostname and hostname != ip_addr:
                return hostname
        except:
            pass
        
        # Fallback: Return IP or Unknown
        return ip_addr

    def get_manufacturer(self, mac_addr):
        """Get device manufacturer from MAC address prefix"""
        prefix = mac_addr[:8].replace(':', '')
        return f"Device ({prefix})"

    def display_devices(self):
        """Display discovered devices with connection duration"""
        print("\n" + "="*70)
        print("📊 DISCOVERED DEVICES")
        print("="*70 + "\n")
        
        if not self.devices:
            print("❌ No devices found on network")
            return
        
        for idx, device in enumerate(self.devices, 1):
            days = device['days_connected']
            duration_str = f"{days} day(s)" if days > 0 else "Today"
            
            print(f"{idx}. Device: {device['hostname']}")
            print(f"   IP Address: {device['ip']}")
            print(f"   MAC Address: {device['mac']}")
            print(f"   Manufacturer: {device['manufacturer']}")
            print(f"   User Assigned: {device['user']}")
            print(f"   First Seen: {device['first_seen']}")
            print(f"   Last Seen: {device['last_seen']}")
            print(f"   🔗 Connected Since: {duration_str}")
            print()

    def export_to_csv(self, filename='devices.csv'):
        """Export device list to CSV"""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'ip', 'mac', 'hostname', 'manufacturer', 
                    'user', 'first_seen', 'last_seen', 'days_connected'
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

    def map_device_name(self, mac_addr, device_name):
        """Map MAC address to device name"""
        self.device_map[mac_addr] = device_name
        self.save_device_database()
        print(f"✅ Mapped {mac_addr} -> {device_name}")

    def save_device_database(self):
        """Save device mapping to database"""
        try:
            with open('device_database.json', 'w') as f:
                json.dump(self.device_map, f, indent=2)
        except Exception as e:
            print(f"⚠️ Could not save database: {e}")

    def save_device_history(self):
        """Save device connection history"""
        try:
            with open('device_history.json', 'w') as f:
                json.dump(self.device_history, f, indent=2)
        except Exception as e:
            print(f"⚠️ Could not save history: {e}")

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
    
    # Examples of mapping devices to users:
    # scanner.map_device_user('AA:BB:CC:DD:EE:FF', 'user@gmail.com')
    # scanner.map_device_name('AA:BB:CC:DD:EE:FF', 'MyLaptop')
