import re
import subprocess
import codecs
from typing import Union
import src.utils  # Assuming utils is used for helper functions

class WPA3Scanner:
    """Handles WPA3 detection logic for Wi-Fi networks."""

    def __init__(self, interface: str):
        self.interface = interface

    def scanForWPA3(self) -> Union[dict[int, dict], bool]:
        """Scan for WPA3 networks and parse scan results."""

        def handleNetwork(_line, result, networks):
            networks.append({
                'ESSID': '',
                'Security type': 'Unknown',
                'BSSID': '',
                'WPA3': False
            })
            networks[-1]['BSSID'] = result.group(1).upper()

        def handleEssid(_line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleSecurityType(_line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'WPA3' in result.group(2):
                    sec = 'WPA3'
                elif 'WPA2' in result.group(2):
                    sec = 'WPA2'
                else:
                    sec = 'Open'
            networks[-1]['Security type'] = sec

        def handleWpa3(_line, result, networks):
            # Specific WPA3 detection (e.g., RSN with WPA3 specific values)
            if 'WPA3' in result.group(1):
                networks[-1]['WPA3'] = True

        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handleNetwork,
            re.compile(r'SSID: (.*)'): handleEssid,
            re.compile(r'(capability): (.+)'): handleSecurityType,
            re.compile(r'(RSN):\t [*] WPA3-Only: (.+)'): handleWpa3  # Example pattern for WPA3 detection
        }

        # Scan networks using iw tool
        command = ['iw', 'dev', self.interface, 'scan']
        iw_scan_process = subprocess.run(command, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = iw_scan_process.stdout.splitlines()

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Error:', line)
                return False

            line = line.strip('\t')

            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        # Filter out non-WPA3 networks
        networks = list(filter(lambda x: x['Security type'] == 'WPA3', networks))

        if not networks:
            return False

        # Sorting by signal strength
        networks.sort(key=lambda x: x.get('Level', 0), reverse=True)

        # Return the network list with WPA3-specific information
        return networks

    def promptWPA3Network(self) -> str:
        """Prompt the user to select a WPA3 network."""
        networks = self.scanForWPA3()

        if not networks:
            print('[-] No WPA3 networks found.')
            return None

        while True:
            try:
                network_no = input('Select WPA3 network (press Enter to refresh): ')

                if network_no.lower() in {'r', '0', ''}:
                    return self.promptWPA3Network()

                if int(network_no) in range(1, len(networks) + 1):
                    return networks[int(network_no) - 1]['BSSID']

                raise IndexError
            except IndexError:
                print('Invalid number')

