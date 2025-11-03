import re
import csv
import codecs
import subprocess
import os
from typing import Union, Dict, List, Tuple, Any

from src.utils import REPORTS_DIR
import src.args
import src.utils

args = src.args.parseArgs()

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
        self.INTERFACE = interface
        self.VULN_LIST = vuln_list if vuln_list else []
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

        reports_fname = os.path.join(REPORTS_DIR, 'stored.csv')
        
        if not os.path.isfile(reports_fname):
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
            print(f"[!] Error reading {reports_fname}, stored networks list may be incomplete.")

    def promptNetwork(self) -> str:
        networks = self._iwScanner()

        if not networks:
            print('[!] No WPS networks found.')
            return ""

        while True:
            try:
                network_no_str = input('Select target (press Enter to refresh): ')

                if network_no_str.lower() in {'r', '0', ''}:
                    if args.clear:
                        src.utils.clearScreen()
                    return self.promptNetwork()

                network_no = int(network_no_str)
                if network_no in networks:
                    return networks[network_no]['BSSID']
                
                print('Invalid number')
            except (ValueError, IndexError):
                print('Invalid number')
            except EOFError:
                print('\nAborting...')
                return ""

    @staticmethod
    def _decode_iw_string(s: str) -> str:
        try:
            return codecs.decode(s, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
        except (UnicodeDecodeError, UnicodeEncodeError):
            return s

    def _handleNetwork(self, result: re.Match, networks: List[Dict]):
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

    def _handleEssid(self, result: re.Match, networks: List[Dict]):
        networks[-1]['ESSID'] = self._decode_iw_string(result.group(1))

    def _handleLevel(self, result: re.Match, networks: List[Dict]):
        try:
            networks[-1]['Level'] = int(float(result.group(1)))
        except (ValueError, IndexError):
            networks[-1]['Level'] = -100

    def _handleSecurityType(self, result: re.Match, networks: List[Dict]):
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

    def _handleWps(self, result: re.Match, networks: List[Dict]):
        networks[-1]['WPS'] = bool(result.group(1))

    def _handleWpsVersion(self, result: re.Match, networks: List[Dict]):
        wps_ver_filtered = result.group(1).replace('* Version2:', '')
        if wps_ver_filtered == '2.0':
            networks[-1]['WPS version'] = '2.0'

    def _handleWpsLocked(self, result: re.Match, networks: List[Dict]):
        try:
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True
        except (ValueError, IndexError):
            pass

    def _handleModel(self, result: re.Match, networks: List[Dict]):
        networks[-1]['Model'] = self._decode_iw_string(result.group(1))

    def _handleModelNumber(self, result: re.Match, networks: List[Dict]):
        networks[-1]['Model number'] = self._decode_iw_string(result.group(1))

    def _handleDeviceName(self, result: re.Match, networks: List[Dict]):
        networks[-1]['Device name'] = self._decode_iw_string(result.group(1))

    @staticmethod
    def _truncateStr(s: str, length: int, postfix='…') -> str:
        if not s:
            s = ""
        if len(s) > length:
            k = length - len(postfix)
            s = s[:k] + postfix
        return s

    @staticmethod
    def _colored(text: str, color: str) -> str:
        colors = {
            'green': '\033[1m\033[92m',
            'dark_green': '\033[32m',
            'red': '\033[1m\033[91m',
            'yellow': '\033[1m\033[93m',
            'end': '\033[00m'
        }
        if color in colors:
            return f"{colors[color]}{text}{colors['end']}"
        return text

    def _printNetworkTable(self, network_list_items: List[Tuple[int, Dict]]):
        print('Network marks: {1} {0} {2} {0} {3} {0} {4}'.format(
            '|',
            self._colored('Vulnerable model', color='green'),
            self._colored('Vulnerable WPS ver.', color='dark_green'),
            self._colored('WPS locked', color='red'),
            self._colored('Already stored', color='yellow')
        ))

        def entryMaxLength(item: str, max_length=27) -> int:
            lengths = [len(entry[1].get(item, '')) for entry in network_list_items]
            if not lengths:
                return max_length + 1
            return min(max(lengths), max_length) + 1

        columm_lengths = {
            '#': 4,
            'sec': entryMaxLength('Security type'),
            'bssid': 18,
            'essid': entryMaxLength('ESSID'),
            'name': entryMaxLength('Device name'),
            'model': entryMaxLength('Model')
        }

        row_format = '{:<{#}} {:<{bssid}} {:<{essid}} {:<{sec}} {:<{#}} {:<{#}} {:<{name}} {:<{model}}'

        print(row_format.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'Ver.', 'WSC name', 'WSC model',
            **columm_lengths
        ))

        if args.reverse_scan:
            network_list_items = network_list_items[::-1]
            
        for n, network in network_list_items:
            model = f'{network["Model"]} {network["Model number"]}'.strip()
            essid = self._truncateStr(network['ESSID'], 25)
            device_name = self._truncateStr(network['Device name'], 27)
            number = f'{n})'
            line = row_format.format(
                number, network['BSSID'], essid,
                network['Security type'], network['Level'],
                network['WPS version'], device_name, model,
                **columm_lengths
            )
            
            color = None
            if (network['BSSID'], network['ESSID']) in self.STORED:
                color = 'yellow'
            elif network['WPS version'] == '1.0':
                color = 'dark_green'
            elif network['WPS locked']:
                color = 'red'
            elif (model in self.VULN_LIST) or (device_name in self.VULN_LIST):
                if model or device_name:
                    color = 'green'

            print(self._colored(line, color=color))

    def _iwScanner(self) -> Union[Dict[int, Dict[str, Any]], bool]:
        networks: List[Dict] = []
        command = ['iw', 'dev', f'{self.INTERFACE}', 'scan']
        
        try:
            iw_scan_process = subprocess.run(command,
                encoding='utf-8', 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT
            )
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as error:
            print (f'[!] Failed to perform an iw scan: \n {error}')
            return False

        lines = iw_scan_process.stdout.splitlines()

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Error:', line)
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