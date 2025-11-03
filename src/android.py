import subprocess
import time

class AndroidNetwork:
    """Manages android Wi-Fi-related settings"""

    def __init__(self):
        self.ENABLED_SCANNING = 0

    def _run_android_cmd(self, cmd: list[str], error_msg: str):
        """Helper function to run subprocess commands with error handling."""
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )
        except FileNotFoundError:
            print(f'[!] {error_msg}: Command "{cmd[0]}" not found.')
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.strip() or e.stdout.strip()
            print(f'{error_msg}: \n {error_output}')
        except OSError as e:
            print(f'{error_msg}: \n {e}')

    def storeAlwaysScanState(self):
        """Stores Initial Wi-Fi 'always-scanning' state, so it can be restored on exit"""
        settings_cmd = ['settings', 'get', 'global', 'wifi_scan_always_enabled']

        try:
            result = subprocess.run(
                settings_cmd,
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout.strip() == '1':
                self.ENABLED_SCANNING = 1
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            print('[-] Failed to get initial Wi-Fi scanning state, assuming it\'s enabled')
            # Maintain backward compatibility by assuming 1 on failure
            self.ENABLED_SCANNING = 1
            
            # Provide more debug info
            if isinstance(e, FileNotFoundError):
                print(f'    [Debug] Error: "settings" command not found.')
            elif hasattr(e, 'stderr') and (e.stderr or e.stdout):
                print(f'    [Debug] Error: {e.stderr.strip() or e.stdout.strip()}')
            else:
                print(f'    [Debug] Error: {e}')


    def disableWifi(self, force_disable: bool = False, whisper: bool = False):
        """Disable Wi-Fi connectivity on Android."""
        if not whisper:
            print('[*] Android: disabling Wi-Fi')

        wifi_disable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'disabled']
        self._run_android_cmd(
            wifi_disable_scanner_cmd,
            '[-] Failed to disable Wi-Fi scanner, skipping'
        )

        if self.ENABLED_SCANNING == 1 or force_disable:
            wifi_disable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'disabled']
            self._run_android_cmd(
                wifi_disable_always_scanning_cmd,
                '[-] Failed to disable always-on Wi-Fi scanning, skipping'
            )

        time.sleep(3)

    def enableWifi(self, force_enable: bool = False, whisper: bool = False):
        """Enable Wi-Fi connectivity on Android."""
        if not whisper:
            print('[*] Android: enabling Wi-Fi')

        wifi_enable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'enabled']
        self._run_android_cmd(
            wifi_enable_scanner_cmd,
            '[!] Failed to enable Wi-Fi scanner, skipping'
        )

        if self.ENABLED_SCANNING == 1 or force_enable:
            wifi_enable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'enabled']
            self._run_android_cmd(
                wifi_enable_always_scanning_cmd,
                '[-] Failed to enable always-on Wi-Fi scanning, skipping'
            )