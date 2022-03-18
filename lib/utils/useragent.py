import random
from loguru import logger
from lib.vars.vars import conf, th, paths
from lib.vars.ua import UA_LIST


def get_random_agent():
    return random.sample(UA_LIST, 1)[0]


def firefox():
    return 'Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0'


def ie():
    return 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)'


def chrome():
    return 'Mozilla/5.0 (Windows NT 5.2) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.122 Safari/534.30'


def opera():
    return 'Opera/9.80 (Windows NT 5.1; U; zh-cn) Presto/2.9.168 Version/11.50'


def iphone():
    return 'Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16'


def google_bot():
    return 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'


def msn_bot():
    return 'msnbot/1.1 (+http://search.msn.com/msnbot.htm)'


def yahoo_bot():
    return 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'
