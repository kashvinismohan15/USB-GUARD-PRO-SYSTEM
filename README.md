# USBGuard Pro - Smart USB Intrusion Prevention System

## 🎯 Project Overview

USBGuard Pro is a lightweight, intelligent USB security monitoring system that detects and prevents malicious USB device activities in real-time. This tool protects against BadUSB attacks, HID injection, malware delivery, and unauthorized data access.

## ✨ Features

### Real-time USB Monitoring

- Automatic detection of USB device connections/disconnections
- Continuous monitoring of device behavior
- Low system resource usage

### Threat Detection

- **HID Injection Detection**: Identifies USB devices masquerading as keyboards
- **BadUSB Detection**: Detects devices with multiple device classes
- **Autorun Detection**: Scans for autorun.inf and suspicious executables
- **Vendor Verification**: Checks against trusted vendor database
- **Reconnection Attack Detection**: Blocks previously malicious devices

### Security Actions

- Automatic blocking of high-risk devices
- Real-time alerts for suspicious activity
- Device quarantine capability
- Threat level classification (SAFE, LOW, MEDIUM, HIGH, CRITICAL)

### Comprehensive Logging

- Connection/disconnection timestamps
- Device usage duration tracking
- Detailed threat descriptions
- Activity history
- SQLite database storage

### User Interface

- Modern GUI with dark theme
- Live monitoring dashboard
- Device logs viewer
- Threat detection reports
- Statistics and analytics

## 📋 Requirements

### System Requirements

- **OS**: Windows 10/11
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 100MB
- **Python**: 3.8 or higher
- **Privileges**: Administrator rights required

### Python Dependencies

```
pywin32==306
wmi==1.5.1
psutil==5.9.8
```

## 🚀 Installation

### Step 1: Install Python

Download and install Python from [python.org](https://www.python.org/downloads/)

### Step 2: Install Dependencies

Open PowerShell as Administrator and run:

```powershell
cd "C:\Users\hanep\Documents\kerja\usb antivirus"
pip install -r requirements.txt
```

### Step 3: Run the Application

```powershell
python gui_application.py
```

## 📖 Usage Guide

### Starting Monitoring

1. Launch the application (run as Administrator)
2. Click **"▶ Start Monitoring"** button
3. System will begin monitoring USB devices

### Understanding Threat Levels

- 🟢 **SAFE**: No threats detected
- 🟡 **LOW**: Unknown vendor, minor concerns
- 🟠 **MEDIUM**: Autorun files detected
- 🔴 **HIGH**: Suspicious HID device
- 🔴 **CRITICAL**: BadUSB or blocked device attempting reconnection

### Viewing Logs

- **Live Monitor Tab**: See real-time device activity
- **Device Logs Tab**: View complete connection history
- **Threat Detections Tab**: Review all security incidents
- **Statistics Tab**: Analyze system metrics

### Blocked Devices

When a device is blocked:

1. System immediately disables the device
2. Alert is displayed in the activity log
3. Entry is created in threat detections
4. Device is added to blocklist

## 🛡️ Security Features Explained

### HID Injection Protection

Detects USB devices that identify as Human Interface Devices (keyboards/mice) but aren't recognized brands. Prevents keystroke injection attacks.

### BadUSB Prevention

Identifies devices advertising multiple device classes simultaneously, a common BadUSB attack characteristic.

### Autorun Protection

Scans newly connected storage devices for autorun.inf files that could execute malware automatically.

### Vendor Whitelist

Pre-configured list of trusted manufacturers:

- SanDisk (0781)
- Kingston (0951, 13FE)
- Logitech (046D)
- Microsoft (045E)
- Apple (05AC)
- And more...

## 📊 Database Schema

### usb_logs Table

Stores all USB device connection records:

- device_id, device_name, vendor_id
- connection_time, disconnection_time, duration
- status, threat_level, activities

### threat_detections Table

Logs all security incidents:

- device_id, detection_time
- threat_type, description, action_taken

## 🔧 Configuration

### Adding Trusted Vendors

Edit `usb_monitor.py`, find `is_trusted_vendor()` function:

```python
trusted_vendors = [
    "0781",  # SanDisk
    "YOUR_VENDOR_ID",  # Add here
]
```

### Adjusting Monitoring Interval

Edit `usb_monitor.py`, line ~270:

```python
time.sleep(2)  # Change this value (seconds)
```

## 🧪 Testing

### Test Cases

1. **Normal USB Flash Drive**: Should be detected as SAFE
2. **Keyboard Connection**: Should be allowed if recognized brand
3. **Unknown Device**: Should show LOW/MEDIUM threat warning
4. **Simulated HID Attack**: Should be blocked (CRITICAL)

### Testing Tools

- USB Rubber Ducky (for HID injection testing)
- Standard USB flash drives
- Various keyboard/mouse devices

## 🎯 Project Objectives

1. ✅ Study USB-based attack methods and countermeasures
2. ✅ Develop lightweight USB intrusion prevention system
3. ✅ Test system functionality and robustness

## 🔮 Future Enhancements

- [ ] Machine learning-based threat detection
- [ ] Network scanning for USB over IP attacks
- [ ] Cloud-based threat intelligence integration
- [ ] Multi-platform support (Linux, macOS)
- [ ] Email/SMS alert notifications
- [ ] Remote management dashboard
- [ ] Device fingerprinting database
- [ ] Behavioral analysis engine

## ⚠️ Important Notes

### Administrator Rights

This tool MUST run with administrator privileges to:

- Monitor USB events at system level
- Disable malicious devices
- Access device hardware information

### Antivirus Interference

Some antivirus software may flag device blocking actions. Add USBGuard Pro to your antivirus whitelist.

### False Positives

- Uncommon but legitimate USB devices may trigger warnings
- Review threat descriptions before taking action
- Add trusted devices to whitelist if needed

## 🐛 Troubleshooting

### Issue: "Access Denied" errors

**Solution**: Run PowerShell/CMD as Administrator

### Issue: WMI errors

**Solution**: Restart Windows Management Instrumentation service:

```powershell
net stop winmgmt
net start winmgmt
```

### Issue: Device not detected

**Solution**:

1. Check monitoring is started
2. Verify USB port is functional
3. Check Windows Device Manager for device visibility

## 📚 References

1. Anderson, R. (2020). _Security Engineering_ (3rd ed.). Wiley.
2. Kaspersky. (2023). USB threat statistics report 2023.
3. NIST. (2022). Guide to malware incident prevention (SP 800-83r2).
4. Wang, Z., & Stavrou, A. (2010). Exploiting smart-phone USB connectivity

## 📄 License

This project is developed for academic purposes as part of Final Year Project requirements at Universiti Kuala Lumpur.

---

**Developed with ❤️ for cybersecurity**
