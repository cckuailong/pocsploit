import os
import traceback
from loguru import logger
from lib.vars.vars import *
from lib.vars.info import BANNER
from lib.core.parse import cmdLineParser
from lib.core.option import initOptions
from lib.controller.loader import loadModule, loadTargets
from lib.controller.engine import run
from lib.core.common import systemQuit
from lib.core.enums import EXIT_STATUS
from lib.core.exception import ToolkitUserQuitException
from lib.core.exception import ToolkitMissingPrivileges
from lib.core.exception import ToolkitSystemException

def main():
    try:
        print(BANNER)
        
        cmdLineOptions.update(cmdLineParser().__dict__)
        initOptions(cmdLineOptions)

        loadModule()
        loadTargets()

        run()
        
        systemQuit(EXIT_STATUS.SYSETM_EXIT)

    except ToolkitMissingPrivileges as e:
        logger.error(e)
        systemQuit(EXIT_STATUS.ERROR_EXIT)

    except ToolkitSystemException as e:
        logger.error(e)
        systemQuit(EXIT_STATUS.ERROR_EXIT)

    except ToolkitUserQuitException:
        systemQuit(EXIT_STATUS.USER_QUIT)
    except KeyboardInterrupt:
        systemQuit(EXIT_STATUS.USER_QUIT)

    except Exception:
        logger.warning(traceback.format_exc())
        logger.warning('It seems like you reached a unhandled exception, please raise a issue via:<https://github.com/cckuailong/pocsploit/issues/new>.')
