import subprocess
import csv
from datetime import datetime
from shutil import which
import logging
from typing import Optional

import src.android
import src.utils

logger = logging.getLogger(__name__)


def add_network(bssid: str, essid: str, wpa_psk: str) -> None:
    """Saves a network to Android or NetworkManager."""
    
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
    if src.utils.isAndroid():
        try:
            # We still need a try here for enableWifi
            android_network = src.android.AndroidNetwork()
            android_network.enableWifi(force_enable=True, whisper=True)
            
            # Use new helper
            if src.utils.run_command(android_connect_cmd, "Failed to add network to Android"):
                added = True
        except Exception as e:
            logger.error(f'Failed to enable Wi-Fi for saving network: {e}')

    elif which('nmcli'):
        # Use new helper
        if src.utils.run_command(networkmanager_connect_cmd, "Failed to add network to NetworkManager"):
            added = True
    else:
        logger.warning('No compatible network manager (Android, NetworkManager) found to save network.')
        return

    if added:
        logger.info('Access Point was saved to your network manager')

def write_result(bssid: str, essid: str, wps_pin: str, wpa_psk: str) -> None:
    """Writes credentials to stored.txt and stored.csv."""
    
    reports_dir = src.utils.REPORTS_DIR
    txt_filename = reports_dir / 'stored.txt'
    csv_filename = reports_dir / 'stored.csv'

    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        write_table_header = not csv_filename.is_file()
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
        
        logger.info(f'Credentials saved to {txt_filename.name}, {csv_filename.name}')
    
    except (IOError, OSError) as e:
        logger.error(f'Failed to write credentials to file: {e}')

def write_pin(bssid: str, pin: str) -> None:
    """Saves a PIN to a session .run file."""
    
    pixiewps_dir = src.utils.PIXIEWPS_DIR
    filename = pixiewps_dir / f"{bssid.replace(':', '').upper()}.run"

    try:
        pixiewps_dir.mkdir(parents=True, exist_ok=True)
        filename.write_text(pin, encoding='utf-8')
        logger.info(f'PIN saved in {filename}')
    
    except (IOError, OSError) as e:
        logger.error(f'Failed to write PIN to file: {e}')