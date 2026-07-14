# Wi-Fi Password Dumper Collection

A collection of utility tools designed to retrieve and export saved Wi-Fi profiles and their corresponding passwords from your local device. This repository contains a native Windows PowerShell script for quick local extraction and a cross-platform Python solution for multi-OS deployment.

---

## ⚠️ Disclaimer
These tools are intended for local system administration, authorized penetration testing audits, troubleshooting, and personal credential recovery. Only run these scripts on devices you own or have explicit, documented authorization to audit.

---

## 🚀 Script 1: Native Windows PowerShell Script
* **File:** `WiFi_Passwords_Dumper.ps1`  
* **Supported OS:** Windows 10 / 11  
* **Execution Time:** < 5 seconds  

Because Windows restricts unsigned script execution by default, you must explicitly bypass the execution policy for this single session.

### Step-by-Step Instructions:
1. Open **PowerShell** with Administrator privileges.
2. Navigate to the script's folder:
   ```powershell
   cd path\to\folder
   ```
3. Run the script using the bypass flag:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\WiFi_Passwords_Dumper.ps1
   ```
4. **View Results:** The script will print the profiles and passwords to the console and automatically save a `.txt` report in the same directory.

---

## 🚀 Script 2: Universal Cross-Platform Python Script
* **File:** `WiFi_Passwords_Dumper_All_OSs.py`  
* **Supported OS:** Windows, macOS, Linux, Android (Rooted)  
* **Requirements:** Python 3.x installed and appropriate OS-level elevated privileges (Admin/Root).

### Step-by-Step Instructions:

#### 1. Install Python (If not already installed)
* **Windows / macOS:** Download and run the installer from [python.org](https://www.python.org/). *(Crucial for Windows: Check the box that says **"Add Python to PATH"** during setup).*
* **Linux:** Run `sudo apt install python3` (Ubuntu/Debian) or `sudo dnf install python3` (Fedora).
* **Android:** Install [Termux](https://termux.dev/) and provision environment: `pkg install python`.

#### 2. Download and Run the Script
Navigate to the directory where you saved `WiFi_Passwords_Dumper_All_OSs.py` and run the command matching your operating system:

* **🪟 For Windows:**  
  Open **Command Prompt** or **PowerShell** as Administrator and run:
  ```cmd
  python WiFi_Passwords_Dumper_All_OSs.py
  ```

* **🍎 For macOS:**  
  Open **Terminal** and execute:
  ```bash
  python3 WiFi_Passwords_Dumper_All_OSs.py
  ```
  > **Note:** macOS will trigger a GUI pop-up prompting for permission to allow Terminal to access the System Keychain. You must type your Mac login password and select **"Always Allow"** for successful extraction.

* **🐧 For Linux:**  
  Open **Terminal** and execute with root privileges:
  ```bash
  sudo python3 WiFi_Passwords_Dumper_All_OSs.py
  ```

* **🤖 For Android (Requires ROOT):**  
  *Unrooted Android physical sandboxing completely prevents reading saved network configurations.*  
  Open **Termux**, escalate to root, and execute:
  ```bash
  su
  cd /sdcard/
  python WiFi_Passwords_Dumper_All_OSs.py
  ```

---

## 📂 Output Format

Upon successful execution, both tools generate a plain text extraction log named `[ComputerName]_Wifi_credentials.txt` in the active working directory.

**Example File Structure:**
```text
==================================================
        WI-FI PASSWORDS EXPORT RESULTS            
==================================================
Generated on: 2026-07-14 16:15:00
Device Name: ENDPOINT-SEC-01
--------------------------------------------------

SSID: Home_Network_5G
Security: WPA2-Personal
Password: SuperSecretPassword123

SSID: Corporate_Guest
Security: Open
Password: [None / Open Network]

==================================================
```

---

## 🛠️ Troubleshooting

* **"Execution Policy" Error (PowerShell):**  
  Ensure you are using the exact execution bypass syntax inline instead of trying to globally modify the system configuration:  
  `powershell -ExecutionPolicy Bypass -File .\WiFi_Passwords_Dumper.ps1`
  
* **"Permission Denied" / Empty Outputs (Python):**  
  The Python script queries low-level system binaries (like `netsh` on Windows, `security` on Mac, or files in `/etc/` on Linux). It **will** fail silently or throw errors if the terminal instance does not have elevated privileges. Ensure you are running as Administrator or using `sudo`.
  
* **Mac Keychain Prompt Denied:**  
  Clicking "Deny" on the security pop-up restricts access to the secure database, forcing the script to output `[Permission Denied]` for targeted profiles.
  
* **Android Directory Failures:**  
  Without active root access granted via a manager like Magisk, Termux cannot pull configurations from protected system paths like `/data/misc/wifi/`.
