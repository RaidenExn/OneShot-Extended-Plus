import sys
import os
import pathlib
import subprocess

# Constants
USER_HOME = str(pathlib.Path.home())
SESSIONS_DIR = f'{USER_HOME}/.OneShot-Extended/sessions/'
PIXIEWPS_DIR = f'{USER_HOME}/.OneShot-Extended/pixiewps/'
REPORTS_DIR  = f'{os.getcwd()}/reports/'

# Function to check if the script is running on Android
def isAndroid():
    """Check if this project is run on Android."""
    return bool(hasattr(sys, 'getandroidapilevel'))

# Function to control the Wi-Fi interface (up or down)
def ifaceCtl(interface: str, action: str):
    """Put an interface up or down."""
    command = ['ip', 'link', 'set', f'{interface}', f'{action}']
    command_output = subprocess.run(
        command, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    command_output_stripped = command_output.stdout.strip()

    # Fix "RF-kill" issues on specific Android devices
    if isAndroid() is False:
        def _rfKillUnblock():
            rfkill_command = ['rfkill', 'unblock', 'wifi']
            subprocess.run(rfkill_command, check=True)

        if 'RF-kill' in command_output_stripped:
            print('[!] RF-kill is blocking the interface, unblocking')
            _rfKillUnblock()  # Will throw CalledProcessError if fails
            return 0

    if command_output.returncode != 0:
        print(f'[!] {command_output_stripped}')

    return command_output.returncode

# Function to clear the terminal screen
def clearScreen():
    """Clear the terminal screen."""
    os.system('clear')

# Function to exit with an error message
def die(text: str):
    """Print an error and exit with a non-zero exit code."""
    sys.exit(f'[!] {text} \n')

# Add the missing functions for logging and saving passwords

def info(msg):
    """Print informational messages with blue color."""
    print(f"\033[1;34m[*]\033[0m {msg}")

def success(msg):
    """Print success messages with green color."""
    print(f"\033[1;32m[+]\033[0m {msg}")

def warning(msg):
    """Print warning messages with yellow color."""
    print(f"\033[1;33m[!]\033[0m {msg}")

def error(msg):
    """Print error messages with red color."""
    print(f"\033[1;31m[✖]\033[0m {msg}")

def savePassword(password, ssid):
    """Save the found password to a file."""
    with open("found_passwords.txt", "a") as file:
        file.write(f"Network: {ssid} - Password: {password}\n")

