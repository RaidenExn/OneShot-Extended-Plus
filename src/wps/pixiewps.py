import subprocess
import logging
from typing import Union

import src.utils # <-- Import utils

logger = logging.getLogger(__name__)

class Data:
    """Stores data used for the pixiewps command."""

    def __init__(self):
        self.clear()

    def getAll(self) -> bool:
        """Check if all pixiewps related variables are set."""
        return bool(self.PKE and self.PKR and self.E_NONCE and self.AUTHKEY
                    and self.E_HASH1 and self.E_HASH2)

    def runPixieWps(self, show_command: bool = False, full_range: bool = False) -> Union[str, bool]:
        """Runs pixiewps and attempts to extract the WPS pin."""
        
        logger.info('Running Pixiewps…')
        command = self._getPixieCmd(full_range)

        if show_command:
            print(' '.join(command)) # This print STAYS

        # --- Use new helper ---
        command_output = src.utils.run_command(
            command,
            'Error running pixiewps'
        )
        
        if not command_output:
            # Error was already logged by run_command
            return False
        # --- End of change ---

        # This print STAYS. It's printing the direct output of the tool.
        print(command_output.stdout)

        # command_output.returncode is 0 because check=True in run_command
        # If it failed, run_command would have returned None
        for line in command_output.stdout.splitlines():
            if '[+]' in line and 'WPS pin' in line:
                pin = line.split(':')[-1].strip()
                return "''" if pin == '<empty>' else pin

        return False # Failed to find pin

    def _getPixieCmd(self, full_range: bool = False) -> list[str]:
        """Generates the command list for the pixiewps tool."""
        
        pixiecmd = [
            'pixiewps',
            '--pke', self.PKE,
            '--pkr', self.PKR,
            '--e-hash1', self.E_HASH1,
            '--e-hash2', self.E_HASH2,
            '--authkey', self.AUTHKEY,
            '--e-nonce', self.E_NONCE
        ]

        if full_range:
            pixiecmd.append('--force')

        return pixiecmd

    def clear(self) -> None:
        """Resets all pixiewps variables to empty strings."""
        self.PKE = ''
        self.PKR = ''
        self.E_HASH1 = ''
        self.E_HASH2 = ''
        self.AUTHKEY = ''
        self.E_NONCE = ''