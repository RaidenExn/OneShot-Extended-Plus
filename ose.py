#!/usr/bin/env python3

#  OneShot-Extended (WPS penetration testing utility) is a fork of the tool with extra features
#  Copyright (C) 2025 chickendrop89
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.

import os
import sys
from shutil import which
from pathlib import Path

import src.wifi.android
import src.wifi.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args


def checkRequirements():
    """Verify requirements are met"""

    if sys.version_info < (3, 9):
        src.utils.die('The program requires Python 3.9 and above')

    if os.getuid() != 0:
        src.utils.die('Run it as root')

    if not which('pixiewps'):
        src.utils.die('Pixiewps is not installed, or not in PATH')


def setupDirectories():
    """Create required directories"""

    old_dir = os.path.expanduser('~/.OSE')
    new_dir = os.path.expanduser('~/.OneShot-Extended')

    # Rename old directory only if it exists and new directory does not
    if os.path.exists(old_dir) and not os.path.exists(new_dir):
        try:
            os.rename(old_dir, new_dir)
            print('[*] Renamed legacy data directory')
        except OSError as e:
            print(f'[!] Failed to rename data directory: {e}')

    for directory in [src.utils.SESSIONS_DIR, src.utils.PIXIEWPS_DIR]:
        os.makedirs(directory, exist_ok=True)  # safer, avoids race conditions


def setupAndroidWifi(android_network: src.wifi.android.AndroidNetwork, enable: bool = False):
    """Configure Android-specific WiFi settings"""

    if enable:
        android_network.enableWifi()
    else:
        android_network.storeAlwaysScanState()
        android_network.disableWifi()


def setupMediatekWifi(wmt_wifi_device: Path):
    """Initialize MediaTek WiFi dev"""

    if not wmt_wifi_device.is_char_device():
        src.utils.die('Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): '
                     '/dev/wmtWifi does not exist or it is not a character device')

    wmt_wifi_device.chmod(0o644)

    # Only write '1' if it's not already set
    current_val = wmt_wifi_device.read_text().strip()
    if current_val != '1':
        wmt_wifi_device.write_text('1', encoding='utf-8')


def scanForNetworks(interface: str, vuln_list: list[str]) -> str:
    """Scan, and prompt user to select network. Returns BSSID"""

    scanner = src.wifi.scanner.WiFiScanner(interface, vuln_list)
    return scanner.promptNetwork()


def handleConnection(args):
    """Main connection logic"""

    if args.bruteforce:
        connection = src.wps.bruteforce.Initialize(args.interface)
    else:
        connection = src.wps.connection.Initialize(
            args.interface,
            args.write,
            args.save,
            args.verbose
        )

    if args.pbc:
        connection.singleConnection(pbc_mode=True)
    else:
        if not args.bssid:
            vuln_list = []
            try:
                with open(args.vuln_list, 'r', encoding='utf-8') as file:
                    vuln_list = file.read().splitlines()
            except FileNotFoundError:
                pass  # empty list if file not found

            if not args.loop:
                print('[*] BSSID not specified (--bssid) — scanning for available networks')

            args.bssid = scanForNetworks(args.interface, vuln_list)

        if args.bssid:
            if args.bruteforce:
                connection.smartBruteforce(
                    args.bssid,
                    args.pin,
                    args.delay
                )
            else:
                connection.singleConnection(
                    args.bssid,
                    args.pin,
                    args.pixie_dust,
                    args.show_pixie_cmd,
                    args.pixie_force
                )


def main():
    """Main os-e code"""

    checkRequirements()
    setupDirectories()

    args = src.args.parseArgs()

    while True:
        android_network = None
        try:
            android_network = src.wifi.android.AndroidNetwork()

            if args.clear:
                src.utils.clearScreen()

            if src.utils.isAndroid() and not args.dts and not args.mtk_wifi:
                setupAndroidWifi(android_network)

            if args.mtk_wifi:
                wmt_wifi_device = Path('/dev/wmtWifi')
                setupMediatekWifi(wmt_wifi_device)

            if src.utils.ifaceCtl(args.interface, action='up'):
                src.utils.die(f'Unable to up interface \'{args.interface}\'')

            handleConnection(args)

            if not args.loop:
                break

            args.bssid = None

        except KeyboardInterrupt:
            if args.loop:
                if input('\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ').lower() == 'y':
                    print('Aborting…')
                    break
                args.bssid = None
            else:
                print('\nAborting…')
                break

        finally:
            if android_network and src.utils.isAndroid() and not args.dts and not args.mtk_wifi:
                setupAndroidWifi(android_network, enable=True)

    if args.iface_down:
        src.utils.ifaceCtl(args.interface, action='down')

    if args.mtk_wifi:
        wmt_wifi_device.write_text('0', encoding='utf-8')


if __name__ == '__main__':
    main()
