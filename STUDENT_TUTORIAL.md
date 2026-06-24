# USBGuard Pro Student Tutorial

## 1. What this system does

USBGuard Pro is a desktop security tool that monitors USB activity in real time.

Main functions:

- Admin system (register and login) with SQL storage
- Real-time USB monitoring dashboard
- New USB insertion notification
- Manual USB block from dashboard
- Activity log (device, time/date, duration, status)
- System tracking (file count, file access estimate, key actions, time-based alerts)
- Unauthorized USB alert system
- Theme switch and wording style switch (including Bang mode)

## 2. Project files

Important files in this project:

- `gui_application.py` - GUI and dashboard
- `usb_monitor.py` - USB monitor logic and SQL backend
- `requirements.txt` - Python dependencies
- `test_usbguard.py` - Automated tests
- `usb_logs.db` - Database file (auto-created on first run)

## 3. Requirements before running

- Python 3.9 or newer
- pip
- OS:
  - Windows 10/11 for full hardware-level USB control
  - macOS/Linux runs in compatible mode (monitoring and logging still work)

Notes:

- `pywin32` and `wmi` are Windows-only dependencies and are auto-skipped on non-Windows systems.

## 4. Setup steps

### Step 1: Open terminal in project folder

```bash
cd "/path/to/usb antivirus"
```

### Step 2: Create virtual environment

```bash
python3 -m venv .venv
```

### Step 3: Activate virtual environment

macOS/Linux:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Windows CMD:

```cmd
.\.venv\Scripts\activate.bat
```

### Step 4: Install dependencies

```bash
python -m pip install -r requirements.txt
```

## 5. How to run the system

```bash
python gui_application.py
```

What happens on first launch:

1. You will see Admin Access screen.
2. If no admin exists, select Register.
3. Create username and password.
4. Login with created account.
5. Dashboard opens.

## 6. Dashboard walkthrough

### A) Controls

- Start Monitoring
- Stop Monitoring
- Refresh Logs
- Manual Block

### B) Main tabs

1. Live Dashboard

- Active USB list in real time
- Activity feed updates as events happen

2. Activity Log

- Connection and disconnection records
- Duration and status entries

3. Threat Alerts

- Threat detections and actions

4. System Events

- USB inserted/removed
- Time threshold alerts
- File count spike events

5. Statistics

- Total sessions
- Threat count
- Blocked count
- Files accessed estimate
- Monitoring uptime

### C) Theme and wording

- Theme switcher: System Blue, System Green, System Amber
- Wording switcher: Standard, Bang

## 7. Manual block flow

1. Go to Live Dashboard.
2. Select an active device row.
3. Click Manual Block.
4. Confirm action.
5. Status updates in UI and log database.

## 8. Testing (must-do before submission)

Run all tests:

```bash
python -m unittest -v
```

Optional syntax check:

```bash
python -m py_compile usb_monitor.py gui_application.py test_usbguard.py
```

Expected test result:

- 3 tests
- 0 failures
- 0 errors

## 9. Troubleshooting

### Issue: GUI does not show

Try:

```bash
pkill -f gui_application.py
python gui_application.py
```

### Issue: Permission or USB control limitations on macOS/Linux

- This is expected for low-level Windows-only actions.
- Full device disable/block at system level works best on Windows with administrator rights.

### Issue: Login fails

- Ensure you are using the correct registered username/password.
- If testing from scratch, remove old DB and restart:

```bash
rm -f usb_logs.db
python gui_application.py
```

## 10. Recommended demo script for student presentation

1. Launch app and login.
2. Show theme switch and Bang wording.
3. Click Start Monitoring.
4. Insert USB and show real-time detection.
5. Show alert and logs update.
6. Use Manual Block on selected device.
7. Open Activity Log and System Events tabs.
8. Open Statistics tab.
9. Run `python -m unittest -v` as final proof of stability.

## 11. Final notes for submission

- Include screenshot of login, live dashboard, and logs.
- Include terminal output of tests.
- Mention platform note clearly:
  - Full USB hardware control on Windows.
  - Compatible monitoring mode on macOS/Linux.
