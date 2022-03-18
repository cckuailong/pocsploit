import queue
import sys
import imp
import os
import IPy
from loguru import logger
from lib.vars.vars import th, conf, paths
from lib.core.enums import TARGET_MODE_STATUS
from lib.vars.info import ESSENTIAL_MODULE_METHODS
from lib.core.exception import ToolkitValueException
from lib.controller.output import SEVERITY_OUTPUT



def loadModule():
    logger.info("Initialize modules...")
    tmp_module_objs = set()
    if os.path.isfile(conf.MODULE_NAME) and conf.MODULE_NAME.endswith('.py'):
        module_name = os.path.splitext(os.path.split(conf.MODULE_NAME)[1])[0]
        fp, pathname, description = imp.find_module(module_name, [os.path.abspath(os.path.dirname(conf.MODULE_NAME))])
        tmp_module_objs.add(imp.load_module(module_name, fp, pathname, description))
    elif os.path.isdir(conf.MODULE_NAME):
        for root, dirs, files in os.walk(conf.MODULE_NAME):
            for file in files:
                if file.endswith('.py'):
                    module_name = os.path.splitext(file)[0]
                    fp, pathname, description = imp.find_module(module_name, [os.path.abspath(root)])
                    tmp_module_objs.add(imp.load_module(module_name, fp, pathname, description))

    fail_set = set()
    for module_obj in tmp_module_objs:
        try:
            if hasattr(module_obj, "info") and module_obj.info()['severity'] not in SEVERITY_OUTPUT:
                logger.warning("[{}] Can't find correct severity in module: [critical,high,medium,low,info]".format(module_obj.__name__))
                fail_set.add(module_obj)
                continue
            for func in ESSENTIAL_MODULE_METHODS:
                if not hasattr(module_obj, func):
                    logger.warning("[{}] Can't find essential method:'{}()' in module，Please modify it.".format(module_obj.__name__, func))
                    fail_set.add(module_obj)
        except ImportError as e:
            logger.error("[{}] Caused this exception\n[Error Msg]: {}\nMaybe you can download this module from pip or easy_install".format(module_obj.__name__, str(e)))
    th.module_objs = tmp_module_objs - fail_set
    logger.info("[Loaded modules] Success: {}, Fail: {}".format(len(th.module_objs), len(fail_set)))
    logger.warning("Failed modules: [{}]".format(",".join([x.__name__ for x in fail_set])))
    if not th.module_objs:
        raise ToolkitValueException('No valid module found.')


def loadTargets():
    logger.info("Initialize targets...")
    th.queue = queue.Queue()
    if conf.TARGET_MODE is TARGET_MODE_STATUS.FILE:
        file_mode()
    elif conf.TARGET_MODE is TARGET_MODE_STATUS.IPMASK:
        net_mode()
    elif conf.TARGET_MODE is TARGET_MODE_STATUS.SINGLE:
        single_target_mode()
    else:
        raise ToolkitValueException('conf.TARGET_MODE value ERROR.')

    logger.info('[Load Target] Total: %s' % str(th.queue.qsize()))


def file_mode():
    for line in open(conf.INPUT_FILE_PATH):
        sub = line.strip()
        if sub:
            th.queue.put(sub)


def net_mode():
    ori_str = conf.NETWORK_STR
    try:
        _list = IPy.IP(ori_str)
    except Exception as e:
        sys.exit(logger.error('Invalid IP/MASK,%s' % e))
    for each in _list:
        th.queue.put(str(each))


def single_target_mode():
    th.queue.put(str(conf.SINGLE_TARGET_STR))
