import os
import glob
import sys
from loguru import logger
from lib.vars.vars import conf, th
from lib.vars.info import GIT_REPOSITORY
from lib.core.enums import TARGET_MODE_STATUS
from lib.utils.register import Register


def initOptions(args):
    checkUpdate(args)
    Output(args)
    ModuleRegister(args)
    EngineRegister(args)
    TargetRegister(args)


def checkUpdate(args):
    if args.sys_update:
        sys.exit(logger.info('Please visit {} to update.'.format(GIT_REPOSITORY)))


def EngineRegister(args):
    thread_num = args.thread_num
    fp_mode = args.fp_mode
    poc_mode = args.poc_mode
    exp_mode = args.exp_mode

    # thread num
    if 0 < thread_num < 10000:
        th.THREADS_NUM = conf.THREADS_NUM = thread_num
        logger.info('Threads Num: %s' % thread_num)
    else:
        msg = 'Invalid input in [-t], range: 1 to 100'
        sys.exit(logger.error(msg))

    def __poc():
        if poc_mode:
            th.DETECT_MODE = "poc"
    
    def __exp():
        if exp_mode:
            th.DETECT_MODE = "exp"

    # fp mode
    th.FP_MODE = args.fp_mode

    msg = "Please select mode with [--poc|--exp]"
    # poc/exp mode
    r = Register(mutex=True, mutex_errmsg=msg)
    r.add(__poc, poc_mode)
    r.add(__exp, exp_mode)
    r.run()


def ModuleRegister(args):
    conf.MODULE_NAME = args.module_name

    # handle input: nothing
    if not conf.MODULE_NAME:
        msg = 'Use -r to load modules. Example: [-s spider] or [-s ./modules/spider.py]'
        sys.exit(logger.error(msg))
    
    # show modules
    show_modules = args.show_modules
    if show_modules:
        if os.path.isfile(conf.MODULE_NAME) and conf.MODULE_NAME.endswith('.py'):
            module_name_list = [conf.MODULE_NAME]
        elif os.path.isdir(conf.MODULE_NAME):
            module_name_list = glob.glob(os.path.join(conf.MODULE_NAME, '*.py'))
        else:
            sys.exit(logger.error("No Valid Module Found"))
        msg = 'Modules Name (total:%s)\n' % str(len(module_name_list) - 1)
        logger.info(msg)
        for each in module_name_list:
            _str = os.path.splitext(os.path.split(each)[1])[0]
            if _str not in ['__init__']:
                logger.info("\033[01;34;34m"+_str+"\033[0m")
        sys.exit(0)


def TargetRegister(args):
    input_file = args.target_file
    input_single = args.target_single
    input_network = args.target_network

    def __file():
        if not os.path.isfile(input_file):
            sys.exit(logger.error('TargetFile not found: %s' % input_file))
        conf.TARGET_MODE = TARGET_MODE_STATUS.FILE
        conf.INPUT_FILE_PATH = input_file

    def __network():
        conf.TARGET_MODE = TARGET_MODE_STATUS.IPMASK
        conf.NETWORK_STR = input_network
        conf.INPUT_FILE_PATH = None

    def __single():
        conf.TARGET_MODE = TARGET_MODE_STATUS.SINGLE
        conf.SINGLE_TARGET_STR = input_single
        conf.INPUT_FILE_PATH = None

    msg = 'Please load targets with [-iS|-iA|-iF|-iN]'
    r = Register(mutex=True, mutex_errmsg=msg)
    r.add(__file, input_file)
    r.add(__network, input_network)
    r.add(__single, input_single)
    r.run()


def Output(args):
    output_file = args.output_path
    quiet = args.quiet_mode

    if quiet:
        logger.remove()
        logger.disable('all')

    if output_file:
        conf.OUTPUT_FILE_PATH = os.path.abspath(output_file)
        logger.add(conf.OUTPUT_FILE_PATH, filter=lambda x: x["level"].name=="SUCCESS", format="{message}")
