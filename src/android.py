import subprocess
import time
import logging
from typing import Optional

import src.utils # <-- Import utils

logger = logging.getLogger(__name__)

class AndroidNetwork:
    """Manages android Wi-Fi-related settings"""

    def __init__(self):
        self.ENABLED_SCANNING: int = 0

    # --- DELETED _run_android_cmd ---
    # It is now replaced by src.utils.run_command

    def storeAlwaysScanState(self) -> None:
        """Stores Initial Wi-Fi 'always-scanning' state, so it can be restored on exit"""
        settings_cmd = ['settings', 'get', 'global', 'wifi_scan_always_enabled']

        # Use the new helper. Run quietly, as failure here is not critical.
        result = src.utils.run_command(
            settings_cmd, 
            "Failed to get Wi-Fi scanning state", 
            quiet=True
        )

        if result and result.stdout.strip() == '1':
            self.ENABLED_SCANNING = 1
        else:
            # Failure is not critical, just log a warning and assume 1
            logger.warning('Failed to get initial Wi-Fi scanning state, assuming it\'s enabled')
            self.ENABLED_SCANNING = 1
            if result:
                logger.debug(f'settings command output: {result.stdout.strip()}')


    def disableWifi(self, force_disable: bool = False, whisper: bool = False) -> None:
        """Disable Wi-Fi connectivity on Android."""
        if not whisper:
            logger.info('Android: disabling Wi-Fi')

        wifi_disable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'disabled']
        # Use new helper
        src.utils.run_command(
            wifi_disable_scanner_cmd,
            'Failed to disable Wi-Fi scanner, skipping'
        )

        if self.ENABLED_SCANNING == 1 or force_disable:
            wifi_disable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'disabled']
            # Use new helper
            src.utils.run_command(
                wifi_disable_always_scanning_cmd,
                'Failed to disable always-on Wi-Fi scanning, skipping'
            )

        time.sleep(3)

    def enableWifi(self, force_enable: bool = False, whisper: bool = False) -> None:
        """Enable Wi-Fi connectivity on Android."""
        if not whisper:
            logger.info('Android: enabling Wi-Fi')

        wifi_enable_scanner_cmd = ['cmd', 'wifi', 'set-wifi-enabled', 'enabled']
        # Use new helper
        src.utils.run_command(
            wifi_enable_scanner_cmd,
            'Failed to enable Wi-Fi scanner, skipping'
        )

        if self.ENABLED_SCANNING == 1 or force_enable:
            wifi_enable_always_scanning_cmd = ['cmd', '-w', 'wifi', 'set-scan-always-available', 'enabled']
            # Use new helper
            src.utils.run_command(
                wifi_enable_always_scanning_cmd,
                'Failed to enable always-on Wi-Fi scanning, skipping'
            )