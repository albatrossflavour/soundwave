import logging

logger = logging.getLogger("transformer")

file_handler = logging.FileHandler("transformer.log")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

logger.root = logger
