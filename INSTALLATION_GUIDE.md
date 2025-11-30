# Personal Antivirus - Installation & Setup Guide

## Quick Start (5 Minutes)

This is your **personal antivirus tool** - runs locally on your PC with **automatic startup**.

### Step 1: Download Files

1. Clone or download all files to your PC:
```bash
git clone https://github.com/rishikumarbommakanti-ops/Network-Device-Scanner.git
cd Network-Device-Scanner
```

### Step 2: Install Python & Dependencies

**Prerequisites:**
- Python 3.8+ (Download from https://www.python.org/downloads/)
- Windows 10/11

**Install dependencies:**
```bash
pip install psutil
```

### Step 3: Setup Autorun (ONE-CLICK)

**This is the key step for autostart on PC boot:**

1. **Right-click** `setup_autorun.bat`
2. **Select "Run as Administrator"**
3. **Follow the prompts**

The installer will:
- ✅ Create Windows startup shortcut
- ✅ Register in Windows registry
- ✅ Create logging directory
- ✅ Install Python dependencies
- ✅ Configure for autorun

### Step 4: Done! It's Running

**The tool is now configured to:**
- 🚀 Run automatically when you turn on your PC
- 📊 Monitor your system for threats
- 📝 Generate security reports
- 💾 Save logs locally

---

## Manual Verification

### Run a Manual Scan

```bash
python personal_antivirus.py
```

### Run Continuous Monitoring

```bash
python personal_antivirus.py --monitor
```

This runs in background and monitors every 5 minutes.

### Check Logs

Logs are saved to:
```
%APPDATA%\PersonalAntivirus\threat_log.json
C:\Users\YourUsername\AppData\Roaming\PersonalAntivirus\
```

---

## What Does It Monitor?

### 🔍 Process Scanning
- Detects suspicious process names (cmd.exe, PowerShell, etc.)
- Identifies potentially malicious command-line arguments
- Whitelists system processes
- Reports risk level for each threat

### 🌐 Network Monitoring
- Tracks outbound network connections
- Detects connections to suspicious ports (4444, 5555, 6666, 9999, 31337)
- Logs remote IP addresses and connection status
- Identifies data exfiltration attempts

### 🛡️ System File Checks
- Monitors hosts file modifications
- Tracks Windows driver changes
- Detects system file tampering
- Reports last modification times

### 📊 ARP Spoofing Detection
- Scans ARP table for spoofing attempts
- Identifies MAC address anomalies
- Detects network layer attacks

---

## Features

### ✨ Local Processing
- **100% Offline** - Runs completely on your PC
- **No Cloud Upload** - Your data stays private
- **No Internet Required** - Works without connection
- **Fast Scanning** - Lightweight & efficient

### 🔐 Security Features
- Threat logging & history
- Risk level classification (HIGH, MEDIUM, LOW)
- Timestamp tracking
- Detailed threat reports
- JSON-based logging for easy parsing

### ⚡ Automation
- Auto-start on Windows boot
- Background monitoring
- Scheduled threat checks
- Automatic log rotation

---

## Troubleshooting

### Issue: Setup script won't run
**Solution:**
1. Right-click `setup_autorun.bat`
2. Select "Run as Administrator"
3. Click "Yes" when prompted

### Issue: Python not found
**Solution:**
```bash
# Add Python to PATH or use full path
C:\Python310\python.exe personal_antivirus.py
```

### Issue: Permission denied on psutil
**Solution:**
```bash
pip install --upgrade psutil
# Or install with sudo if needed
```

### Issue: Autorun not working
**Manual setup:**
1. Press `Win+R`
2. Type: `shell:startup`
3. Create a shortcut to `personal_antivirus.py` there

### Issue: Can't find log files
**Check here:**
```
C:\Users\YourUsername\AppData\Roaming\PersonalAntivirus\threat_log.json
```

---

## Usage Examples

### Example 1: Quick Scan
```bash
python personal_antivirus.py
```
Output: Full threat report + saves to log

### Example 2: Background Monitoring
```bash
python personal_antivirus.py --monitor
```
Output: Continuous monitoring every 5 minutes

### Example 3: Read Log File
```bash
type "%APPDATA%\PersonalAntivirus\threat_log.json"
```

---

## Advanced Configuration

### Change Python Location in setup_autorun.bat

If Python is installed elsewhere, edit line ~40:
```batch
set PYTHON_PATH=C:\Python310\python.exe
```

### Adjust Monitoring Interval

Edit `personal_antivirus.py` line ~165:
```python
antivirus.run_continuous_monitoring(interval=300)  # 300 seconds = 5 minutes
```

### Add Custom Suspicious Keywords

Edit line ~24 in `personal_antivirus.py`:
```python
self.suspicious_keywords = [
    'cmd.exe', 'powershell', 'mshta', 'wscript', 'cscript',
    'certutil', 'bitsadmin', 'regsvcs', 'regasm',
    'YOUR_CUSTOM_KEYWORD'  # Add here
]
```

---

## Uninstalling

### Remove Autorun

1. **From Startup folder:**
   - Press `Win+R`
   - Type: `shell:startup`
   - Delete `PersonalAntivirus.lnk`

2. **From Registry:**
   - Press `Win+R`
   - Type: `regedit`
   - Navigate to: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   - Delete `PersonalAntivirus` entry

3. **Delete files:**
   - Delete the Network-Device-Scanner folder
   - Delete logs: `%APPDATA%\PersonalAntivirus\`

---

## Support & Issues

For issues or feature requests:
- Check GitHub Issues: https://github.com/rishikumarbommakanti-ops/Network-Device-Scanner/issues
- Review this guide again
- Check log files for error messages

---

## System Requirements

- **OS:** Windows 10/11
- **Python:** 3.8 or higher
- **RAM:** 50 MB minimum
- **Disk:** 100 MB for logs (per year)
- **Admin Rights:** Required for first-time setup

---

## Privacy Notice

✅ **Completely Private**
- No data sent to cloud
- No telemetry
- No ads or tracking
- Runs 100% offline
- You control all logs

---

## License

This tool is open-source and free to use for personal security monitoring.

**Version:** 1.0  
**Last Updated:** December 2025
