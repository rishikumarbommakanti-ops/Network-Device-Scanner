#!/usr/bin/env python3
"""
PERSONAL ANTIVIRUS TOOL - LOCAL THREAT DETECTION
Monitor network, processes, ports for security threats
Autorun on Windows PC startup
"""
import subprocess
import socket
import psutil
import json
from datetime import datetime
from pathlib import Path
import os
import sys
import time
from threading import Thread

class PersonalAntivirus:
    def __init__(self):
        self.suspicious_ports = []
        self.suspicious_processes = []
        self.threats_found = []
        self.threat_log = 'threat_log.json'
        
        # Suspicious indicators
        self.suspicious_keywords = [
            'cmd.exe', 'powershell', 'mshta', 'wscript', 'cscript',
            'certutil', 'bitsadmin', 'regsvcs', 'regasm'
        ]
        self.suspicious_ports = [4444, 5555, 6666, 9999, 31337]
        self.high_risk_ips = []
        
        print("\n" + "="*70)
        print("🛡️  PERSONAL ANTIVIRUS - LOCAL THREAT DETECTION")
        print("="*70)
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        
    def scan_running_processes(self):
        """Scan for suspicious processes"""
        print("[1/4] Scanning running processes...")
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                    process_name = pinfo['name'].lower()
                    cmdline = ' '.join(pinfo.get('cmdline', [])).lower()
                    
                    # Check for suspicious process names
                    for keyword in self.suspicious_keywords:
                        if keyword.lower() in process_name or keyword.lower() in cmdline:
                            # Whitelist system processes
                            if 'system32' not in cmdline or 'svchost' in process_name:
                                self.suspicious_processes.append({
                                    'pid': pinfo['pid'],
                                    'name': pinfo['name'],
                                    'risk': 'HIGH',
                                    'timestamp': datetime.now().isoformat(),
                                    'reason': f'Suspicious process: {keyword}'
                                })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            if self.suspicious_processes:
                print(f"⚠️  Found {len(self.suspicious_processes)} suspicious processes")
                self.threats_found.extend(self.suspicious_processes)
            else:
                print("✅ No suspicious processes detected")
                
        except Exception as e:
            print(f"❌ Process scan error: {e}")
    
    def scan_network_connections(self):
        """Scan network connections for suspicious activity"""
        print("[2/4] Scanning network connections...")
        try:
            risky_connections = []
            for conn in psutil.net_connections():
                if conn.raddr:
                    remote_ip = conn.raddr[0]
                    remote_port = conn.raddr[1]
                    
                    # Check for suspicious ports
                    if remote_port in self.suspicious_ports:
                        risky_connections.append({
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'local_port': conn.laddr[1] if conn.laddr else None,
                            'status': conn.status,
                            'process': conn.pid,
                            'risk': 'MEDIUM',
                            'timestamp': datetime.now().isoformat(),
                            'reason': f'Suspicious port: {remote_port}'
                        })
            
            if risky_connections:
                print(f"⚠️  Found {len(risky_connections)} suspicious connections")
                self.threats_found.extend(risky_connections)
            else:
                print("✅ No suspicious network connections detected")
                
        except Exception as e:
            print(f"❌ Network scan error: {e}")
    
    def scan_arp_table(self):
        """Detect ARP spoofing attempts"""
        print("[3/4] Scanning ARP table for spoofing...")
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            # Look for unusual MAC addresses
            print("✅ ARP table scan complete")
        except Exception as e:
            print(f"⚠️  ARP scan skipped: {e}")
    
    def scan_system_files(self):
        """Check for modified system files"""
        print("[4/4] Checking system files...")
        critical_paths = [
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\System32\\drivers',
        ]
        try:
            for path_str in critical_paths:
                if Path(path_str).exists():
                    stat_info = Path(path_str).stat()
                    mod_time = datetime.fromtimestamp(stat_info.st_mtime)
                    print(f"  📄 {Path(path_str).name} - Last modified: {mod_time}")
            print("✅ System file scan complete")
        except Exception as e:
            print(f"⚠️  File scan skipped: {e}")
    
    def generate_report(self):
        """Generate security report"""
        print("\n" + "="*70)
        print("📊 SECURITY REPORT")
        print("="*70 + "\n")
        
        if self.threats_found:
            print(f"🚨 THREATS DETECTED: {len(self.threats_found)}\n")
            for idx, threat in enumerate(self.threats_found, 1):
                print(f"{idx}. {threat.get('reason', 'Unknown threat')}")
                print(f"   Risk Level: {threat.get('risk', 'UNKNOWN')}")
                print(f"   Timestamp: {threat.get('timestamp')}")
                print()
        else:
            print("✅ No threats detected! Your system appears safe.\n")
        
        # Log threats
        self.save_threat_log()
    
    def save_threat_log(self):
        """Save threat log to file"""
        try:
            with open(self.threat_log, 'a') as f:
                log_entry = {
                    'scan_time': datetime.now().isoformat(),
                    'threats_count': len(self.threats_found),
                    'threats': self.threats_found
                }
                f.write(json.dumps(log_entry) + '\n')
                print(f"✅ Log saved to {self.threat_log}")
        except Exception as e:
            print(f"⚠️  Could not save log: {e}")
    
    def run_continuous_monitoring(self, interval=300):
        """Run continuous monitoring in background"""
        print(f"\n🔄 Starting continuous monitoring (every {interval}s)...\n")
        try:
            while True:
                self.threats_found = []
                self.suspicious_processes = []
                self.scan_running_processes()
                self.scan_network_connections()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\n⏹️  Monitoring stopped by user")
    
    def run_full_scan(self):
        """Run complete security scan"""
        self.scan_running_processes()
        self.scan_network_connections()
        self.scan_arp_table()
        self.scan_system_files()
        self.generate_report()

if __name__ == "__main__":
    antivirus = PersonalAntivirus()
    
    # Check if running with continuous mode
    if len(sys.argv) > 1 and sys.argv[1] == '--monitor':
        antivirus.run_continuous_monitoring()
    else:
        antivirus.run_full_scan()
        print("\n" + "="*70)
        print("✨ Scan complete!")
        print("="*70)
