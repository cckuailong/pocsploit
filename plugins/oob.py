import requests
import time
import random
import string
from conf.config import *


def gen_oob_domain():
    flag = "".join(random.choice(string.ascii_letters) for _ in range(0, 10)).lower()
    return "{}.{}".format(flag, DNSLOG_IDENTIFY), flag

def gen_oob_url():
    flag = "".join(random.choice(string.ascii_letters) for _ in range(0, 10)).lower()
    return "http://{}.{}/".format(flag, DNSLOG_IDENTIFY), flag


def verify_request(type, flag):
    retVal = False
    counts = 3
    url = "{uri}/v1/records?token={token}&type={type}&filter={flag}".format(uri=DNSLOG_URI, token=DNSLOG_TOKEN, type=type, flag=flag)
    while counts:
        try:
            time.sleep(3)
            resp = requests.get(url, timeout=5)
            # print(resp.text)
            if resp and resp.status_code == 200 and flag in str(resp.content):
                retVal = True
                break
        except:
            time.sleep(1)

        counts -= 1
    return retVal