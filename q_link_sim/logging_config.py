import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logging(log_file_path: str = 'app.log', level=logging.INFO):
    """
    Configures logging for the application.

    Args:
        log_file_path (str): Path to the log file.
        level (int): Logging level (e.g., logging.INFO, logging.DEBUG).
    """
    # Ensure the log directory exists
    log_dir = os.path.dirname(log_file_path)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Create a logger
    logger = logging.getLogger()
    logger.setLevel(level)

    # Clear existing handlers to prevent duplicate logs
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    # Create a file handler
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(level)

    # Create a console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    # Create a formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Suppress overly verbose logs from external libraries
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
    logging.getLogger('web3').setLevel(logging.WARNING)
    logging.getLogger('eth_account').setLevel(logging.WARNING)
    logging.getLogger('paho').setLevel(logging.WARNING)

    logger.info(f"Logging configured. Logs will be written to {log_file_path} with level {logging.getLevelName(level)}.")

if __name__ == '__main__':
    # Example usage for testing logging configuration
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")
