import os
import subprocess
import csv
from datetime import datetime
from shutil import which
from pathlib import Path

import src.android
import src.utils

class WiFiCollector:

    @staticmethod
    def addNetwork(bssid: str, essid: str, wpa_psk: str):
        android_connect_cmd = [
            'cmd', '-w', 'wifi',
            'connect-network', f"{essid}",
            'wpa2', f"{wpa_psk}", 
            '-b', f"{bssid}"
        ]

        networkmanager_connect_cmd = [
            'nmcli', 'connection', 'add', 
            'type', 'wifi', 
            'con-name', f"{essid}",
            'ssid', f"{essid}", 
            'wifi-sec.psk', f"{wpa_psk}",
            'wifi-sec.key-mgmt', 'wpa-psk'
        ]

        added = False
        if src.utils.isAndroid() is True:
            try:
                android_network = src.android.AndroidNetwork()
                android_network.enableWifi(force_enable=True, whisper=True)
                subprocess.run(
                    android_connect_cmd, 
                    check=True, 
                    capture_output=True, 
                    text=True
                )
                added = True
            except (subprocess.CalledProcessError, FileNotFoundError, OSError) as error:
                error_msg = error.stderr or error.stdout or str(error)
                print(f'[!] Failed to add network to Android network manager: \n {error_msg}')

        elif which('nmcli'):
            try:
                subprocess.run(
                    networkmanager_connect_cmd, 
                    check=True, 
                    capture_output=True, 
                    text=True
                )
                added = True
            except (subprocess.CalledProcessError, FileNotFoundError, OSError) as error:
                error_msg = error.stderr or error.stdout or str(error)
                print(f'[!] Failed to add network to NetworkManager: \n {error_msg}')
        else:
            print('[*] No compatible network manager (Android, NetworkManager) found to save network.')
            return

        if added:
            print('[*] Access Point was saved to your network manager')

    @staticmethod
    def writeResult(bssid: str, essid: str, wps_pin: str, wpa_psk: str):
        reports_dir = src.utils.REPORTS_DIR
        filename_base = os.path.join(reports_dir, 'stored')
        txt_filename = filename_base + '.txt'
        csv_filename = filename_base + '.csv'

        try:
            Path(reports_dir).mkdir(parents=True, exist_ok=True)
            write_table_header = not os.path.isfile(csv_filename)
            date_str = datetime.now().strftime('%d.%m.%Y %H:%M')

            with open(txt_filename, 'a', encoding='utf-8') as file:
                file.write('{}\nBSSID: {}\nESSID: {}\nWPS PIN: {}\nWPA PSK: {}\n\n'.format(
                    date_str, bssid, essid, wps_pin, wpa_psk
                ))

            with open(csv_filename, 'a', newline='', encoding='utf-8') as file:
                csv_writer = csv.writer(file,
                    delimiter=';', quoting=csv.QUOTE_ALL
                )

                if write_table_header:
                    csv_writer.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])

                csv_writer.writerow([date_str, bssid, essid, wps_pin, wpa_psk])

            print(f'[*] Credentials saved to {txt_filename}, {csv_filename}')
        
        except (IOError, OSError) as e:
            print(f'[!] Failed to write credentials to file: {e}')

    @staticmethod
    def writePin(bssid: str, pin: str):
        pixiewps_dir = src.utils.PIXIEWPS_DIR
        filename = os.path.join(pixiewps_dir, f"{bssid.replace(':', '').upper()}.run")

        try:
            Path(pixiewps_dir).mkdir(parents=True, exist_ok=True)
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(pin)

            print(f'[*] PIN saved in {filename}')
        
        except (IOError, OSError) as e:
            print(f'[!] Failed to write PIN to file: {e}')