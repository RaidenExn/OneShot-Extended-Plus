import os
import sys
from shutil import which
from pathlib import Path

import src.android
import src.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args

def checkRequirements():
    if sys.version_info < (3, 9):
        src.utils.die('The program requires Python 3.9 and above')

    if os.getuid() != 0:
        src.utils.die('Run it as root')

    if not which('pixiewps'):
        src.utils.die('Pixiewps is not installed, or not in PATH')

def setupDirectories():
    old_dir = Path.home() / '.OSE'
    new_dir = Path.home() / '.OneShot-Extended'

    if old_dir.exists():
        try:
            old_dir.rename(new_dir)
            print('[*] Renamed legacy data directory')
        except OSError as e:
            print(f'[!] Failed to rename data directory: {e}')

    for directory in [src.utils.SESSIONS_DIR, src.utils.PIXIEWPS_DIR]:
        Path(directory).mkdir(parents=True, exist_ok=True)

def setupAndroidWifi(android_network: src.android.AndroidNetwork, enable: bool = False):
    if enable:
        android_network.enableWifi()
    else:
        android_network.storeAlwaysScanState()
        android_network.disableWifi()

def setupMediatekWifi(wmt_wifi_device: Path):
    if not wmt_wifi_device.is_char_device():
        src.utils.die('Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): '
                     f'{wmt_wifi_device} does not exist or it is not a character device')

    try:
        wmt_wifi_device.chmod(0o644)
        wmt_wifi_device.write_text('1', encoding='utf-8')
    except (IOError, OSError) as e:
        src.utils.die(f'Failed to write to {wmt_wifi_device}: {e}')


def scanForNetworks(interface: str, vuln_list: list[str]) -> str:
    scanner = src.scanner.WiFiScanner(interface, vuln_list)
    return scanner.promptNetwork()

def handleConnection(args):
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
                pass
            except (IOError, OSError) as e:
                print(f'[!] Could not read vulnerability list: {e}')

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
    checkRequirements()
    setupDirectories()

    args = src.args.parseArgs()

    wmt_wifi_device = Path('/dev/wmtWifi') if args.mtk_wifi else None
    android_network = None

    try:
        if src.utils.isAndroid() and not args.dts and not args.mtk_wifi:
            android_network = src.android.AndroidNetwork()
    except Exception as e:
        print(f'[!] Failed to initialize AndroidNetwork: {e}')


    while True:
        try:
            if args.clear:
                src.utils.clearScreen()

            if android_network:
                setupAndroidWifi(android_network)

            if args.mtk_wifi and wmt_wifi_device:
                setupMediatekWifi(wmt_wifi_device)

            if src.utils.ifaceCtl(args.interface, action='up'):
                src.utils.die(f'Unable to up interface \'{args.interface}\'')

            handleConnection(args)

            if not args.loop:
                break

            args.bssid = None

        except KeyboardInterrupt:
            if args.loop:
                try:
                    if input('\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ').lower() == 'y':
                        print('Aborting…')
                        break
                    args.bssid = None
                except EOFError:
                    print('\nAborting…')
                    break
            else:
                print('\nAborting…')
                break
        
        except Exception as e:
            print(f'[!] An unexpected error occurred: {e}')
            if not args.loop:
                break
            print('[*] Restarting loop...')


        finally:
            if android_network:
                try:
                    setupAndroidWifi(android_network, enable=True)
                except Exception as e:
                    print(f'[!] Failed to restore Android Wi-Fi state: {e}')

    if args.iface_down:
        src.utils.ifaceCtl(args.interface, action='down')

    if args.mtk_wifi and wmt_wifi_device and wmt_wifi_device.exists():
        try:
            wmt_wifi_device.write_text('0', encoding='utf-8')
        except (IOError, OSError) as e:
            print(f'[!] Failed to write to {wmt_wifi_device} on exit: {e}')

if __name__ == '__main__':
    main()