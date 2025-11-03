import re
import csv
import codecs
import subprocess
import os
import logging
from typing import Union, Dict, List, Tuple, Any, Optional
from pathlib import Path

# --- Import Rich ---
from rich.console import Console
from rich.table import Table

from src.utils import REPORTS_DIR
import src.args
import src.utils

args = src.args.parseArgs()
logger = logging.getLogger(__name__)

# (All REGEX constants remain the same)
REGEX_BSS = re.compile(r'BSS (\S+)( )?\(on \w+\)')
REGEX_SSID = re.compile(r'SSID: (.*)')
REGEX_SIGNAL = re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm')
REGEX_CAPABILITY = re.compile(r'(capability): (.+)')
REGEX_RSN = re.compile(r'(RSN):\t [*] Version: (\d+)')
REGEX_WPA = re.compile(r'(WPA):\t [*] Version: (\d+)')
REGEX_WPS_VER = re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)')
REGEX_WPS_V2 = re.compile(r' [*] Version2: (.+)')
REGEX_WPS_AUTH = re.compile(r' [*] Authentication suites: (.+)')
REGEX_WPS_LOCK = re.compile(r' [*] AP setup locked: (0x[0-9]+)')
REGEX_MODEL = re.compile(r' [*] Model: (.*)')
REGEX_MODEL_NUM = re.compile(r' [*] Model Number: (.*)')
REGEX_DEV_NAME = re.compile(r' [*] Device name: (.*)')


class WiFiScanner:

    def __init__(self, interface: str, vuln_list: list[str] = None):
        self.INTERFACE: str = interface
        self.VULN_LIST: list[str] = vuln_list if vuln_list else []
        self.STORED: List[Tuple[str, str]] = []
        self.matchers = {
            REGEX_BSS: self._handleNetwork,
            REGEX_SSID: self._handleEssid,
            REGEX_SIGNAL: self._handleLevel,
            REGEX_CAPABILITY: self._handleSecurityType,
            REGEX_RSN: self._handleSecurityType,
            REGEX_WPA: self._handleSecurityType,
            REGEX_WPS_VER: self._handleWps,
            REGEX_WPS_V2: self._handleWpsVersion,
            REGEX_WPS_AUTH: self._handleSecurityType,
            REGEX_WPS_LOCK: self._handleWpsLocked,
            REGEX_MODEL: self._handleModel,
            REGEX_MODEL_NUM: self._handleModelNumber,
            REGEX_DEV_NAME: self._handleDeviceName
        }

        # Use pathlib path
        reports_fname = REPORTS_DIR / 'stored.csv'
        
        if not reports_fname.is_file():
            return

        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8') as file:
                csv_reader = csv.reader(file,
                    delimiter=';', quoting=csv.QUOTE_ALL
                )
                
                next(csv_reader)
                for row in csv_reader:
                    if len(row) >= 3:
                        self.STORED.append((row[1], row[2]))
        except (FileNotFoundError, IOError):
            pass
        except (csv.Error, StopIteration):
            logger.error(f"Error reading {reports_fname}, stored networks list may be incomplete.")

    def promptNetwork(self) -> str:
        networks = self._iwScanner()

        if not networks:
            logger.warning('No WPS networks found.')
            return ""

        while True:
            try:
                # This print is for input, it STAYS
                network_no_str = input('Select target (press Enter to refresh): ')

                if network_no_str.lower() in {'r', '0', ''}:
                    if args.clear:
                        src.utils.clearScreen()
                    return self.promptNetwork()

                network_no = int(network_no_str)
                if network_no in networks:
                    return networks[network_no]['BSSID']
                
                print('Invalid number') # This print STAYS
            except (ValueError, IndexError):
                print('Invalid number') # This print STAYS
            except EOFError:
                print('\nAborting...') # This print STAYS
                return ""

    @staticmethod
    def _decode_iw_string(s: str) -> str:
        try:
            return codecs.decode(s, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
        except (UnicodeDecodeError, UnicodeEncodeError):
            return s
    
    # (All _handle... methods remain the same)
    
    def _handleNetwork(self, result: re.Match, networks: List[Dict]) -> None:
        networks.append(
            {
                'ESSID': '',
                'Security type': 'Unknown',
                'WPS': False,
                'WPS version': '1.0',
                'WPS locked': False,
                'Model': '',
                'Model number': '',
                'Device name': '',
                'BSSID': result.group(1).upper()
            }
        )

    def _handleEssid(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]['ESSID'] = self._decode_iw_string(result.group(1))

    def _handleLevel(self, result: re.Match, networks: List[Dict]) -> None:
        try:
            networks[-1]['Level'] = int(float(result.group(1)))
        except (ValueError, IndexError):
            networks[-1]['Level'] = -100

    def _handleSecurityType(self, result: re.Match, networks: List[Dict]) -> None:
        sec = networks[-1]['Security type']
        if result.group(1) == 'capability':
            if 'Privacy' in result.group(2):
                sec = 'WEP'
            else:
                sec = 'Open'
        elif sec == 'WEP':
            if result.group(1) == 'RSN':
                sec = 'WPA2'
            elif result.group(1) == 'WPA':
                sec = 'WPA'
        elif sec == 'WPA':
            if result.group(1) == 'RSN':
                sec = 'WPA/WPA2'
        elif sec == 'WPA2':
            if result.group(1) == 'PSK SAE':
                sec = 'WPA2/WPA3'
            elif result.group(1) == 'WPA':
                sec = 'WPA/WPA2'
        networks[-1]['Security type'] = sec

    def _handleWps(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]['WPS'] = bool(result.group(1))

    def _handleWpsVersion(self, result: re.Match, networks: List[Dict]) -> None:
        wps_ver_filtered = result.group(1).replace('* Version2:', '')
        if wps_ver_filtered == '2.0':
            networks[-1]['WPS version'] = '2.0'

    def _handleWpsLocked(self, result: re.Match, networks: List[Dict]) -> None:
        try:
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True
        except (ValueError, IndexError):
            pass

    def _handleModel(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]['Model'] = self._decode_iw_string(result.group(1))

    def _handleModelNumber(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]['Model number'] = self._decode_iw_string(result.group(1))

    def _handleDeviceName(self, result: re.Match, networks: List[Dict]) -> None:
        networks[-1]['Device name'] = self._decode_iw_string(result.group(1))


    def _printNetworkTable(self, network_list_items: List[Tuple[int, Dict]]) -> None:
        console = Console() # Use stdout by default

        # Header/Legend
        console.print(
            "Network marks: [bold green]Vulnerable model[/] | "
            "[green]Vulnerable WPS ver.[/] | "
            "[bold red]WPS locked[/] | "
            "[bold yellow]Already stored[/]"
        )
        
        # Define the table
        table = Table()
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("BSSID", style="magenta", no_wrap=True)
        table.add_column("ESSID")
        table.add_column("Sec.", no_wrap=True)
        table.add_column("PWR", justify="right", no_wrap=True)
        table.add_column("Ver.", no_wrap=True)
        table.add_column("WSC name")
        table.add_column("WSC model")

        if args.reverse_scan:
            network_list_items = network_list_items[::-1]
            
        for n, network in network_list_items:
            model = f'{network["Model"]} {network["Model number"]}'.strip()
            
            # Manual truncation (can be removed if you want rich to handle it)
            essid = network['ESSID']
            if len(essid) > 25:
                essid = essid[:25] + '…'
            
            device_name = network['Device name']
            if len(device_name) > 27:
                device_name = device_name[:27] + '…'
            
            # Determine row style based on color logic
            style = None # Default
            if (network['BSSID'], network['ESSID']) in self.STORED:
                style = "bold yellow"
            elif network['WPS version'] == '1.0':
                style = "green"
            elif network['WPS locked']:
                style = "bold red"
            elif (model in self.VULN_LIST) or (device_name in self.VULN_LIST):
                if model or device_name:
                    style = "bold green"
    
            table.add_row(
                f"{n})",
                network['BSSID'],
                essid,
                network['Security type'],
                str(network['Level']),
                network['WPS version'],
                device_name,
                model,
                style=style # Apply style to the whole row
            )
            
        console.print(table)

    def _iwScanner(self) -> Union[Dict[int, Dict[str, Any]], bool]:
        networks: List[Dict] = []
        command = ['iw', 'dev', f'{self.INTERFACE}', 'scan']
        
        # --- This block is now updated to use the new helper ---
        iw_scan_process = src.utils.run_command(command, log_errors=False)
        
        if iw_scan_process is None:
            # FileNotFoundError or OSError, helper already logged it
            logger.error('Failed to run "iw" command. Is it installed?')
            return False
        
        if iw_scan_process.returncode != 0:
            error_output = (iw_scan_process.stderr or iw_scan_process.stdout).strip()
            logger.error(f'Failed to perform an iw scan: \n {error_output}')
            return False
        # --- End of updated block ---

        lines = iw_scan_process.stdout.splitlines()

        for line in lines:
            # This check is still useful for specific `iw` errors
            if line.startswith('command failed:'):
                logger.error(f'Error: {line}')
                return False

            line = line.strip('\t')
            for regexp, handler in self.matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(res, networks)
                    break

        networks = list(filter(lambda x: bool(x.get('WPS')), networks))

        if not networks:
            return False

        networks.sort(key=lambda x: x.get('Level', -100), reverse=True)

        network_list = {(i + 1): network for i, network in enumerate(networks)}
        network_list_items = list(network_list.items())

        self._printNetworkTable(network_list_items)

        return network_list