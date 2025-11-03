import subprocess
from typing import Union

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
        
        print('[*] Running Pixiewps…')
        command = self._getPixieCmd(full_range)

        if show_command:
            print(' '.join(command))

        try:
            command_output = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding='utf-8',
                text=True
            )
        except FileNotFoundError:
            print(f'[!] Error: "pixiewps" command not found. Is it installed and in your PATH?')
            return False
        except OSError as e:
            print(f'[!] OS error running pixiewps: {e}')
            return False

        # Always print pixiewps output for the user
        print(command_output.stdout)

        if command_output.returncode == 0:
            for line in command_output.stdout.splitlines():
                if '[+]' in line and 'WPS pin' in line:
                    pin = line.split(':')[-1].strip()
                    # Handle the '<empty>' pin case, returning a string "''"
                    return "''" if pin == '<empty>' else pin

        # Failed to find pin or pixiewps exited with an error
        return False

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

    def clear(self):
        """Resets all pixiewps variables to empty strings."""
        
        self.PKE = ''
        self.PKR = ''
        self.E_HASH1 = ''
        self.E_HASH2 = ''
        self.AUTHKEY = ''
        self.E_NONCE = ''