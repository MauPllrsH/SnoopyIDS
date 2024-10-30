import logging

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/app/ids_server.log')
        ]
    )
    return logging.getLogger('ids_server')

logger = setup_logger()