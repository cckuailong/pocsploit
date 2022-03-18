import sys
from loguru import logger
from lib.core.enums import EXIT_STATUS
from lib.core.exception import ToolkitValueException

def systemQuit(status=EXIT_STATUS.SYSETM_EXIT):
    if status == EXIT_STATUS.SYSETM_EXIT:
        logger.info('System Normal exit.')
    elif status == EXIT_STATUS.USER_QUIT:
        logger.error('User exit!')
    elif status == EXIT_STATUS.ERROR_EXIT:
        logger.error('System Error exit.')
    else:
        raise ToolkitValueException('Invalid status code: %s' % str(status))
    sys.exit(0)