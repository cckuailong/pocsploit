from concurrent.futures import ThreadPoolExecutor, wait, as_completed, ALL_COMPLETED
from loguru import logger
from lib.vars.vars import th
from lib.controller.output import SEVERITY_OUTPUT


def scan(target, module_obj):
    result = {}
    if th.FP_MODE:
        if module_obj.fingerprint(target):
            logger.info(f"[FP] {target} target the fingerprint, do poc/exp next")
            if th.DETECT_MODE == "poc":
                result = module_obj.poc(target)
            elif th.DETECT_MODE == "exp":
                result = module_obj.exp(target)
        else:
            logger.warning(f"[FP] {target} not the fingerprint")
    else:
        if th.DETECT_MODE == "poc":
            result = module_obj.poc(target)
        elif th.DETECT_MODE == "exp":
            result = module_obj.exp(target)
    if result:
        logger.success("[{}]{} {}".format(module_obj.__name__, SEVERITY_OUTPUT[result["info"]["severity"]], result["payload"]))

def run():
    with ThreadPoolExecutor(max_workers=th.THREADS_NUM) as executor:
        all_tasks = []
        while True:
            if th.queue.qsize() > 0:
                target = th.queue.get(timeout=1)
                for module_obj in th.module_objs:
                    all_tasks.append(executor.submit(scan, target, module_obj))
            else:
                break
        
        wait(all_tasks, return_when=ALL_COMPLETED)
    
    # while True:
    #     if th.queue.qsize() > 0:
    #         target = th.queue.get(timeout=1)
    #         for module_obj in th.module_objs:
    #             print(target, module_obj)
    #             scan(target, module_obj)
    #     else:
    #         break
