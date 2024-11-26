import logging
import os

LOGGING_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../logs")
logging.basicConfig(level=logging.INFO)

class Loggable:
    def __init__(self, log_type: str, instance_name: str, log_level: int = logging.INFO):
        self.log_name = log_type + ":" + instance_name

        self.logger = logging.getLogger(self.log_name)
        self.logger.setLevel(log_level)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(context)s] %(message)s",
            datefmt="%H:%M:%S"
        )

        file_handler = logging.FileHandler(f"{LOGGING_DIR}/{self.log_name}.log")
        file_handler.setFormatter(formatter)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        filter_instance = NameFilter(self.log_name)
        self.logger.addFilter(filter_instance)
        self.logger.propagate = False


class NameFilter(logging.Filter):
    def __init__(self, log_name):
        super().__init__()
        self.log_name = log_name

    def filter(self, record):
        record.context = self.log_name
        return True
