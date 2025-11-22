
import subprocess
import re

def run(cmd):
    try:
        return subprocess.check_output(cmd, encoding='utf-8').strip()
    except Exception:
        return ""

def get_wifi_info_macos():
    devices = run(['networksetup', '-listallhardwareports'])
    wifi_interface = None
    for block in devices.split("\n\n"):
        if "Wi-Fi" in block or "AirPort" in block:
            match = re.search(r"Device: (\w+)", block)
            if match:
                wifi_interface = match.group(1)
                break
    if not wifi_interface:
        print("WiFi-интерфейс не найден.")
        return

    print(f"WiFi-интерфейс: {wifi_interface}")

    # Получаем SSID и BSSID
    ssid_str = run(['networksetup', '-getairportnetwork', wifi_interface])
    if "You are not associated" in ssid_str:
        print("Вы не подключены к WiFi-сети.")
        ssid = None
    else:
        print(ssid_str)
        ssid = ssid_str.split(": ", 1)[-1]

    # IP адрес
    ifconfig = run(['ifconfig', wifi_interface])
    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', ifconfig)
    if ip_match:
        print("IP адрес:", ip_match.group(1))

    # MAC-адрес точки доступа (BSSID), если есть подключение и airport доступен
    if ssid:
        airport = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
        airport_info = run([airport, '-I'])
        bssid_match = re.search(r'BSSID: (.+)', airport_info)
        if bssid_match:
            print("BSSID (MAC точки доступа):", bssid_match.group(1).strip())

    # MAC-адрес интерфейса
    mac_match = re.search(r'ether ([0-9a-f:]{17})', ifconfig)
    if mac_match:
        print("MAC вашего WiFi-интерфейса:", mac_match.group(1))

if __name__ == "__main__":
    get_wifi_info_macos()
