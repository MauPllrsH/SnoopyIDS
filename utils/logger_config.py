import logging
import os

def setup_logger():
    # Set log path with environment variable fallback
    log_path = os.environ.get('LOG_FILE_PATH', '/app/ids_server.log')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_path)
        ]
    )
    return logging.getLogger('ids_server')

logger = setup_logger()