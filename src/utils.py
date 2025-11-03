import sys
import os
from pathlib import Path
import subprocess
import logging
from typing import Optional

# Get a logger for this module
logger = logging.getLogger(__name__)

# --- Use pathlib for all path definitions ---
USER_HOME = Path.home()
BASE_DIR = USER_HOME / '.OneShot-Extended'
SESSIONS_DIR = BASE_DIR / 'sessions'
PIXIEWPS_DIR = BASE_DIR / 'pixiewps'
REPORTS_DIR = Path.cwd() / 'reports' # Use Path.cwd() instead of os.getcwd()

# --- NEW Centralized Subprocess Runner ---
def run_command(cmd: list[str], log_errors: bool = True) -> Optional[subprocess.CompletedProcess]:
    """
    Runs an external command, logging errors uniformly.
    Returns the CompletedProcess object on success or failure.
    Returns None only on FileNotFoundError or OSError.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        if result.returncode != 0 and log_errors:
            error_output = (result.stderr or result.stdout).strip()
            # Don't log error for "command failed:" as scanner.py handles it
            if "command failed:" not in error_output:
                logger.error(f'Command failed: {" ".join(cmd)}\n{error_output}')
        
        return result
        
    except FileNotFoundError:
        if log_errors:
            logger.error(f'Command not found: "{cmd[0]}"')
    except OSError as e:
        if log_errors:
            logger.error(f'OS error running command: {" ".join(cmd)}\n{e}')
    
    return None
# --- End of new helper ---


def isAndroid() -> bool:
    return bool(hasattr(sys, 'getandroidapilevel'))

def ifaceCtl(interface: str, action: str) -> int:
    """Brings an interface up or down."""
    command = ['ip', 'link', 'set', interface, action]

    def _rfKillUnblock() -> bool:
        rfkill_command = ['rfkill', 'unblock', 'wifi']
        result = run_command(rfkill_command) # Logs errors by default
        return bool(result and result.returncode == 0)

    # Run the command. Don't log errors yet.
    result = run_command(command, log_errors=False)
    
    if result is None:
        logger.error(f'Failed to run "ip" command. Is it installed?')
        return 1

    if result.returncode == 0:
        return 0 # Success

    # Command failed. Now we log the error and check for RF-kill.
    command_output_stripped = (result.stderr or result.stdout).strip()
    logger.error(f'Failed to set interface {action}: \n{command_output_stripped}')

    if 'RF-kill' in command_output_stripped and not isAndroid():
        logger.warning('RF-kill is blocking the interface, attempting to unblock...')
        if _rfKillUnblock():
            logger.info('Retrying command...')
            retry_result = run_command(command) # Log errors on retry
            if retry_result and retry_result.returncode == 0:
                return 0 # Success on retry
        else:
            logger.error('Failed to unblock RF-kill. Interface state unchanged.')

    return 1

def clearScreen() -> None:
    os.system('clear')

def die(text: str) -> None:
    logger.critical(text)
    sys.exit(1)