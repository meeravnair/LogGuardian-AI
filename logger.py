"""
LogGuardian AI Logger Module.
Sets up professional logging with colors for the console and write logs to file.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add colors to console logs."""
    
    COLORS = {
        logging.DEBUG: Fore.BLUE,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, "")
        message = super().format(record)
        if log_color:
            # Colorize the level name or entire line
            levelname_str = f"[{record.levelname}]"
            color_levelname = f"{log_color}{levelname_str}{Style.RESET_ALL}"
            message = message.replace(levelname_str, color_levelname)
        return message

def setup_logger(name: str = "LogGuardian") -> logging.Logger:
    """
    Sets up and returns a configured logger.
    
    Args:
        name: Name of the logger.
        
    Returns:
        A logging.Logger object.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Avoid adding duplicate handlers if already configured
    if logger.handlers:
        return logger

    # Ensure log directory exists
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "platform.log")

    # Console Handler (with Colors)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_fmt = "%(asctime)s [%(levelname)s] (%(filename)s:%(lineno)d) - %(message)s"
    console_formatter = ColoredFormatter(console_fmt, datefmt="%Y-%m-%d %H:%M:%S")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File Handler (Rotating, No Colors for log files)
    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)
    file_fmt = "%(asctime)s [%(levelname)s] (%(name)s) (%(filename)s:%(lineno)d) - %(message)s"
    file_formatter = logging.Formatter(file_fmt, datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger

# Export standard logger
log = setup_logger()
log.info("LogGuardian AI Log System Initialized.")
