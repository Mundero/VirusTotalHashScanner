import logging
import os
import sys


def setup_logger(
    name: str = None,
    log_file: str = None,
    level: int = logging.INFO
) -> logging.Logger:
    """
    Set up and return a logger with console and file handlers.
    
    :param name: Logger name
    :param log_file: Path to log file
    :param level: Logging level (default: INFO)
    :return: Configured Logger instance
    """

    if name is None:
        # Use script filename (without extension) as logger name
        name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
        if not name:  # Fallback if running in interactive mode
            name = "interactive"


    if log_file is None:
        script_path = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
        script_dir = os.path.dirname(script_path) if script_path else os.getcwd()
        logs_dir = os.path.join(script_dir, "logs")
        log_file = os.path.join(logs_dir, f"{name}.log")
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent adding multiple handlers if logger already has them
    if not logger.handlers:
        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)

        # File handler
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
        file_handler.setLevel(level)

        # Formatter
        formatter = logging.Formatter(
            "[{asctime}]-[{levelname}] - {message}",
            style="{",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        # Add handlers
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger


