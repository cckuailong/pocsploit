import os

VERSION = '0.0.1'
PROJECT = "pocsploit"
AUTHOR = 'cckuailong'
PLATFORM = os.name
LICENSE = 'MIT'

# essential methods/functions in custom modules (such as function poc())
ESSENTIAL_MODULE_METHODS = ['info', 'fingerprint', 'poc', 'exp']

GIT_REPOSITORY = "https://github.com/cckuailong/pocsploit"

BANNER = '''
                                 \033[01;31;31m__      _ __ \033[0m
    \033[01;33;33m____  ____  _____\033[0m\033[01;31;31m_________  / /___  (_) /_\033[0m
   \033[01;33;33m/ __ \/ __ \/ ___\033[0m\033[01;31;31m/ ___/ __ \/ / __ \/ / __/\033[0m
  \033[01;33;33m/ /_/ / /_/ / /__\033[0m\033[01;31;31m(__  ) /_/ / / /_/ / / /_  \033[0m
 \033[01;33;33m/ .___/\____/\___/\033[0m\033[01;31;31m____/ .___/_/\____/_/\__/  \033[0m
\033[01;33;33m/_/                   \033[0m\033[01;31;31m/_/                     \033[0m
    \033[01;37m{\033[01;m Version %s by %s \033[01;37m}\033[0m
\n''' % (VERSION, AUTHOR)