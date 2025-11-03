import logging
import sys

class ColorFormatter(logging.Formatter):
    """Custom formatter to add colors and prefixes to log messages."""

    # ANSI Color Codes
    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.FORMATS = {
            logging.DEBUG: f"[{self.GREY}D{self.RESET}] %(message)s",
            logging.INFO: f"[{self.GREEN}*{self.RESET}] %(message)s",
            logging.WARNING: f"[{self.YELLOW}-{self.RESET}] %(message)s",
            logging.ERROR: f"[{self.RED}!{self.RESET}] %(message)s",
            logging.CRITICAL: f"[{self.BOLD_RED}!{self.RESET}] %(message)s"
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def setup_logging(verbose: bool = False):
    """Configures the root logger."""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create a stream handler to output to stderr
    # Using stderr is standard for logs, keeping stdout for potential data output
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColorFormatter())
    
    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()
        
    logger.addHandler(handler)