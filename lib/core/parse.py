import argparse
import sys
from lib.vars.info import VERSION


def cmdLineParser():
    parser = argparse.ArgumentParser(description='powered by cckuailong',
                                     usage='python3 pocsploit.py -iS "http://xxxx/" -r "modules/" -t 100 --poc',
                                     add_help=False)

    engine = parser.add_argument_group('ENGINE')

    engine.add_argument('-t', metavar='THREAD', dest="thread_num", type=int, default=10,
                        help='num of threads/concurrent, 10 by default')
    engine.add_argument('--fp', dest="fp_mode", default=False, action='store_true',
                        help='fp mode')
    engine.add_argument('--poc', dest="poc_mode", default=False, action='store_true',
                        help='poc mode')
    engine.add_argument('--exp', dest="exp_mode", default=False, action='store_true',
                        help='exp mode')

    module = parser.add_argument_group('MODULE')

    module.add_argument('-r', metavar='MODULE', dest="module_name", type=str, default='modules/',
                        help='load module by name (-r jboss-rce) or path (-r ./modules/)')
    module.add_argument('--modules', dest="show_modules", default=False, action='store_true',
                        help='show available modules and exit')

    target = parser.add_argument_group('TARGET')

    target.add_argument('-iS', metavar='TARGET', dest="target_single", type=str, default='',
                        help="scan a single target (e.g. www.wooyun.org)")
    target.add_argument('-iF', metavar='FILE', dest="target_file", type=str, default='',
                        help='load targets from targetFile (e.g. ./data/wooyun_domain)')
    target.add_argument('-iN', metavar='IP/MASK', dest="target_network", type=str, default='',
                        help='generate IP from IP/MASK. (e.g. 127.0.0.0/24)')

    output = parser.add_argument_group('OUTPUT')

    output.add_argument('-o', metavar='FILE', dest="output_path", type=str, default='',
                        help='output file path&name. default in ./output/')
    output.add_argument('-q', '--quiet', dest="quiet_mode", default=False, action='store_true',
                        help='disable screen output')

    system = parser.add_argument_group('SYSTEM')

    system.add_argument('-v', '--version', action='version', version=VERSION,
                        help="show program's version number and exit")
    system.add_argument('-h', '--help', action='help',
                        help='show this help message and exit')
    system.add_argument('--update', dest="sys_update", default=False, action='store_true',
                        help='update POC-T from github source')

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args
