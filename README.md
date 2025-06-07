# 🔐 Keylogger Detector

A lightweight Python-based tool for detecting potential keyloggers and spyware on Windows systems by scanning active processes, registry startup entries, and common malware directories.

---

## 🚀 Features

- ✅ Scans **running processes** for known keylogger-related keywords.
- ✅ Checks **Windows Registry** startup entries for suspicious executables.
- ✅ Searches **temporary and startup folders** for suspicious scripts and executables.
- ✅ Detects potentially **hidden or lightweight keyloggers** (<500KB in size).

---

## 🖥️ System Requirements

- **OS**: Windows 10 or higher
- **Python**: 3.6+
- **Privileges**: Administrator (recommended for full access)

---

## 🔧 Installation

1. Clone the repository:
```python
   
    git clone https://github.com/your-username/keylogger-detector.git
    cd keylogger-detector
```
2. Install the dependencies (only psutil required):

```python
    pip install psutil
```
---
## ▶️ Usage
- Run the detector:

`python keylogger_detector.py`

- Example output:
  
```bash
=== Enhanced Keylogger Detector ===

[*] Scanning running processes...
[✓] No suspicious processes found.
[*] Scanning registry startup entries...
[✓] No suspicious registry startup entries found.
[*] Scanning temporary and startup directories...
[✓] No suspicious files detected in common malware locations.

[✔] Scan complete. Stay safe!
```
---
## 🧪 Detailed Scan Results

### 1. 🧠 Running Process Analysis

- Status: ✅ No matches found.

- Scanned Processes: All currently active processes

#### Detection Keywords:
`keylogger`, `hook`, `sniffer`, `spy`,` capture`, `record`, `keystroke`

#### Result:
  No process names or executable paths contained suspicious indicators.

### 2. 🧾 Registry Startup Entries

- Status: ✅ Clean

- Scanned Registry Paths:

    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

    - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`

#### Result:
No suspicious auto-start registry entries were detected.

### 3. 📁 Suspicious Files in Startup & Temp Folders
- Status: ✅ No threats found

- Scanned Directories:

    - `%TEMP%`

    - `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

#### Suspicious File Criteria:

 - Extensions: `.exe`, `.bat`,` .vbs`,` .py`,` .jar`

- File Size: Less than 500 KB (likely hidden spyware)

#### Result:
No executable scripts or files matching keylogger traits were identified.

---

## ✅ Conclusion
The system was scanned for common indicators of keylogging software.
No suspicious processes, startup entries, or hidden scripts were detected.

 |🛡️ Recommendation: Continue routine scans and monitor for unexpected behaviors. Combine this tool with real-time antivirus protection for maximum security.
