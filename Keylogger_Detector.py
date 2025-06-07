import psutil
import os
import re
import winreg
import time
from pathlib import Path

# Suspicious indicators
SUSPICIOUS_KEYWORDS = [
    "keylogger", "hook", "sniffer", "spy", "capture", "record", "keystroke"
]

SUSPICIOUS_DIRS = [
    os.getenv("TEMP"),
    os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
]

SUSPICIOUS_EXTENSIONS = [".exe", ".bat", ".vbs", ".py", ".jar"]

def detect_suspicious_processes():
    flagged = False
    print("[*] Scanning running processes...")
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pname = proc.info['name'].lower()
            pexe = str(proc.info.get('exe', '')).lower()
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in pname or keyword in pexe:
                    print(f"[!] Suspicious process: {pname} (PID: {proc.pid})")
                    flagged = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not flagged:
        print("[✓] No suspicious processes found.")

def scan_registry_startup():
    print("[*] Scanning registry startup entries...")
    keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]
    flagged = False
    for hive, path in keys:
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    value_lower = value.lower()
                    for keyword in SUSPICIOUS_KEYWORDS:
                        if keyword in value_lower:
                            print(f"[!] Suspicious registry entry: {name} -> {value}")
                            flagged = True
        except Exception:
            continue

    if not flagged:
        print("[✓] No suspicious registry startup entries found.")

def scan_suspicious_files():
    print("[*] Scanning temporary and startup directories...")
    flagged = False
    for directory in SUSPICIOUS_DIRS:
        if not os.path.isdir(directory):
            continue
        for root, dirs, files in os.walk(directory):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        if size < 500000:  # Likely not a legitimate installer or app
                            print(f"[!] Suspicious file: {file_path} ({size} bytes)")
                            flagged = True
                    except Exception:
                        continue
    if not flagged:
        print("[✓] No suspicious files detected in common malware locations.")

def main():
    print("=== Enhanced Keylogger Detector ===\n")
    detect_suspicious_processes()
    scan_registry_startup()
    scan_suspicious_files()
    print("\n[✔] Scan complete. Stay safe!")

if __name__ == "__main__":
    main()
