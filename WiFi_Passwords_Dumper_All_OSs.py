import subprocess
import platform
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

def is_admin():
    try:
        return os.geteuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()

def get_windows_data():
    output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
    profiles = [line.split(":")[-1].strip() for line in output.splitlines() if "All User Profile" in line]
    
    results = []
    for p in profiles:
        try:
            out = subprocess.check_output(f'netsh wlan show profile name="{p}" key=clear', shell=True, text=True)
            pwd, sec = "[None / Open Network]", "Open"
            for line in out.splitlines():
                if "Key Content" in line: pwd = line.split(":")[-1].strip()
                if "Authentication" in line: sec = line.split(":")[-1].strip()
            results.append((p, sec, pwd))
        except:
            results.append((p, "Unknown", "[Error reading]"))
    return results

def get_mac_data():
    cmd = 'defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist KnownNetworks | grep "SSIDString"'
    try:
        output = subprocess.check_output(cmd, shell=True, text=True)
        profiles = list(set([line.split('"')[-2] for line in output.splitlines() if "=" in line]))
    except:
        profiles = []
        
    results = []
    for p in profiles:
        try:
            pwd = subprocess.check_output(f'security find-generic-password -wa "{p}"', shell=True, text=True, stderr=subprocess.DEVNULL).strip()
            results.append((p, "Unknown (Keychain)", pwd))
        except:
            results.append((p, "Open / Permission Denied", "[None / Open Network]"))
    return results

def get_linux_data():
    path = "/etc/NetworkManager/system-connections/"
    if not os.path.exists(path): return []
    
    results = []
    for f in os.listdir(path):
        if f.endswith('.nmconnection') or '.' not in f:
            profile = f.replace('.nmconnection', '')
            try:
                with open(f"{path}{f}", 'r') as file:
                    content = file.read()
                    pwd, sec = "[None / Open Network]", "Open"
                    for line in content.splitlines():
                        if line.startswith("psk="): pwd = line.split("=")[1]
                        if line.startswith("key-mgmt="): sec = line.split("=")[1].upper()
                    results.append((profile, sec, pwd))
            except:
                results.append((profile, "Unknown", "[Permission Denied]"))
    return results

def get_android_data():
    paths = ["/data/misc/wifi/WifiConfigStore.xml", "/data/misc/wifi/wpa_supplicant.conf"]
    for path in paths:
        if os.path.exists(path):
            try:
                output = subprocess.check_output(f'su -c cat {path}', shell=True, text=True)
                if path.endswith(".xml"):
                    root = ET.fromstring(output)
                    return [(n.find(".//string[@name='SSID']").text.strip('"'), "Unknown", n.find(".//string[@name='PreSharedKey']").text if n.find(".//string[@name='PreSharedKey']") is not None else "[None]") for n in root.iter() if n.tag == "Network" and n.find(".//string[@name='SSID']") is not None]
                else:
                    # Legacy wpa_supplicant parsing
                    res, cur_ssid = [], None
                    for line in output.splitlines():
                        if 'ssid=' in line: cur_ssid = line.split('=')[1].strip('"')
                        elif 'psk=' in line and cur_ssid: res.append((cur_ssid, "WPA-PSK", line.split('=')[1].strip('"'))); cur_ssid = None
                    return res
            except: return [("ERROR", "Root access failed", "Check permissions")]
    return [("ERROR", "No config files found", "Is device rooted?")]

def main():
    if not is_admin():
        print("ERROR: This script must be run as Administrator / Root / sudo.")
        sys.exit(1)

    os_name = platform.system()
    pc_name = platform.node()
    filename = f"{pc_name}_Wifi_credentials.txt"
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"""==================================================
        WI-FI PASSWORDS EXPORT RESULTS            
==================================================
Generated on: {timestamp}
Device Name: {pc_name}
--------------------------------------------------"""
    
    print(f"\n{header}")
    
    # Fetch data based on OS
    if os_name == "Windows": data = get_windows_data()
    elif os_name == "Darwin": data = get_mac_data()
    elif os_name == "Linux":
        data = get_android_data() if os.path.exists("/system/build.prop") else get_linux_data()
    else:
        print(f"Unsupported OS: {os_name}"); sys.exit(1)

    # Write to file and console
    with open(filename, "w", encoding="utf-8") as f:
        f.write(header + "\n")
        
        for ssid, sec, pwd in data:
            if ssid == "ERROR":
                block = f"\nSSID: {pwd}\nSecurity: Error\nPassword: {sec}"
            else:
                block = f"\nSSID: {ssid}\nSecurity: {sec}\nPassword: {pwd}"
            
            print(block)
            f.write(block + "\n")

        footer = f"""
==================================================
Total profiles found: {len(data)}
File saved to: {os.path.abspath(filename)}
=================================================="""
        
        print(footer)
        f.write(footer + "\n")

if __name__ == "__main__":
    main()