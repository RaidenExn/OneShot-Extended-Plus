import sys
import os
from pathlib import Path
import subprocess

USER_HOME = str(Path.home())
BASE_DIR = f'{USER_HOME}/.OneShot-Extended'
SESSIONS_DIR = f'{BASE_DIR}/sessions/'
PIXIEWPS_DIR = f'{BASE_DIR}/pixiewps/'
REPORTS_DIR = f'{os.getcwd()}/reports/'

def isAndroid():
    return bool(hasattr(sys, 'getandroidapilevel'))

def ifaceCtl(interface: str, action: str):
    command = ['ip', 'link', 'set', interface, action]

    def _rfKillUnblock():
        rfkill_command = ['rfkill', 'unblock', 'wifi']
        try:
            subprocess.run(
                rfkill_command, 
                check=True, 
                capture_output=True, 
                text=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            print(f'[!] Failed to unblock interface: \n {error}')
            return False

    try:
        command_output = subprocess.run(
            command,
            encoding='utf-8',
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
    except FileNotFoundError:
        print (f'[!] Error: "ip" command not found. Is it installed and in your PATH?')
        return 1
    except OSError as e:
        print (f'[!] OS error trying to run "ip" command: {e}')
        return 1

    command_output_stripped = command_output.stdout.strip()

    if 'RF-kill' in command_output_stripped and not isAndroid():
        print('[-] RF-kill is blocking the interface, attempting to unblock...')
        if _rfKillUnblock():
            print('[-] Retrying command...')
            try:
                command_output = subprocess.run(
                    command,
                    encoding='utf-8',
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )
                command_output_stripped = command_output.stdout.strip()
            except (FileNotFoundError, OSError) as e:
                print(f'[!] Error on retry: {e}')
                return 1
        else:
            print('[!] Failed to unblock RF-kill. Interface state unchanged.')

    if command_output.returncode != 0 and command_output_stripped:
        print(f'[!] {command_output_stripped}')

    return command_output.returncode

def clearScreen():
    os.system('clear')

def die(text: str):
    sys.exit(f'[!] {text}')