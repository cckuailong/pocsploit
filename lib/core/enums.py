class CONTENT_STATUS:
    IN_PROGRESS = 0
    COMPLETE = 1


class EXIT_STATUS:
    SYSETM_EXIT = 0
    ERROR_EXIT = 1
    USER_QUIT = 2


class POC_RESULT_STATUS:
    FAIL = 0
    SUCCESS = 1
    RETRAY = 2


class TARGET_MODE_STATUS:
    FILE = 9
    SINGLE = 8
    IPMASK = 7
    RANGE = 6
    API = 5


class PROXY_TYPE:  # keep same with SocksiPy(import socks)
    PROXY_TYPE_SOCKS4 = SOCKS4 = 1
    PROXY_TYPE_SOCKS5 = SOCKS5 = 2
    PROXY_TYPE_HTTP = HTTP = 3
    PROXY_TYPE_HTTP_NO_TUNNEL = 4
