import os
import sys
from shutil import which
from pathlib import Path
import logging
import time  # <-- Import time

import src.android
import src.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args
from src.logger import setup_logging

# Get a logger for this module
logger = logging.getLogger(__name__)

def checkRequirements():
    if sys.version_info < (3, 9):
        src.utils.die('The program requires Python 3.9 and above')

    if os.getuid() != 0:
        src.utils.die('Run it as root')

    required_commands = ['pixiewps', 'iw', 'ip', 'rfkill']
    missing_commands = []

    for cmd in required_commands:
        if not which(cmd):
            missing_commands.append(cmd)

    if missing_commands:
        src.utils.die(
            'Missing required commands: '
            f'{", ".join(missing_commands)}'
            '\nPlease install them and ensure they are in your PATH.'
        )
    
    logger.debug('All required commands found.')

def setupDirectories():
    old_dir = Path.home() / '.OSE'
    new_dir = src.utils.BASE_DIR

    if old_dir.exists():
        try:
            old_dir.rename(new_dir)
            logger.info('Renamed legacy data directory')
        except OSError as e:
            logger.warning(f'Failed to rename data directory: {e}')

    for directory in [src.utils.SESSIONS_DIR, src.utils.PIXIEWPS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)

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
    # --- This function is modified ---
    
    if args.bruteforce:
        connection = src.wps.bruteforce.Initialize(args.interface, args)
    else:
        connection = src.wps.connection.Initialize(
            args.interface,
            args.write,
            args.save
        )

    if args.pbc:
        # --- Start Timer ---
        start_time = time.monotonic()
        
        connection.singleConnection(pbc_mode=True)
        
        # --- End Timer and Log ---
        end_time = time.monotonic()
        logger.info(f"PBC attack finished in {end_time - start_time:.2f} seconds.")
            
    else:
        if not args.bssid:
            vuln_list = []
            try:
                with open(args.vuln_list, 'r', encoding='utf-8') as file:
                    vuln_list = [line for line in (line.strip() for line in file) if line]
                logger.info(f'Loaded vulnerability list: {len(vuln_list)} entries from {args.vuln_list}')
            except FileNotFoundError:
                logger.warning(f'Vulnerability list not found at {args.vuln_list}. Proceeding without it.')
            except (IOError, OSError) as e:
                logger.warning(f'Could not read vulnerability list: {e}')

            if not args.loop:
                logger.info('BSSID not specified (--bssid) — scanning for available networks')

            # Scanning is done *before* the timer starts
            args.bssid = scanForNetworks(args.interface, vuln_list)

        if args.bssid:
            # --- Start Timer ---
            start_time = time.monotonic()
            attack_type = "Bruteforce" # Default
            
            if args.bruteforce:
                connection.smartBruteforce(
                    args.bssid,
                    args.pin,
                    args.delay
                )
            else:
                attack_type = "PIN/Pixie" # More specific
                connection.singleConnection(
                    args.bssid,
                    args.pin,
                    args.pixie_dust,
                    args.show_pixie_cmd,
                    args.pixie_force
                )
            
            # --- End Timer and Log ---
            end_time = time.monotonic()
            logger.info(f"{attack_type} attack on {args.bssid} finished in {end_time - start_time:.2f} seconds.")

def main():
    args = src.args.parseArgs()
    
    setup_logging(verbose=args.verbose)
    
    logger.debug('Logging initialized')

    checkRequirements()
    setupDirectories()

    wmt_wifi_device = Path('/dev/wmtWifi') if args.mtk_wifi else None
    android_network = None

    try:
        if src.utils.isAndroid() and not args.dts and not args.mtk_wifi:
            android_network = src.android.AndroidNetwork()
    except Exception as e:
        logger.error(f'Failed to initialize AndroidNetwork: {e}')


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

            handleConnection(args) # This function now handles its own timing

            if not args.loop:
                break

            args.bssid = None

        except KeyboardInterrupt:
            if args.loop:
                try:
                    if input('\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ').lower() == 'y':
                        logger.warning('Aborting…')
                        break
                    args.bssid = None
                except EOFError:
                    logger.warning('\nAborting…')
                    break
            else:
                logger.warning('\nAborting…')
                break
        
        except Exception as e:
            logger.error(f'An unexpected error occurred: {e}')
            if not args.loop:
                break
            logger.info('Restarting loop...')


        finally:
            if android_network:
                try:
                    setupAndroidWifi(android_network, enable=True)
                except Exception as e:
                    logger.warning(f'Failed to restore Android Wi-Fi state: {e}')

    if args.iface_down:
        src.utils.ifaceCtl(args.interface, action='down')

    if args.mtk_wifi and wmt_wifi_device and wmt_wifi_device.exists():
        try:
            wmt_wifi_device.write_text('0', encoding='utf-8')
        except (IOError, OSError) as e:
            logger.error(f'Failed to write to {wmt_wifi_device} on exit: {e}')

if __name__ == '__main__':
    main()