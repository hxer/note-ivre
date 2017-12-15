#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

"""
This program runs scans and produces output files importable with
ivre scan2db.
"""


from __future__ import print_function
import atexit
import fcntl
from functools import reduce
import multiprocessing
import os
import re
import resource
import select
import shutil
import subprocess
import sys
import termios
import time


from future.utils import viewitems


import ivre.agent
import ivre.geoiputils
import ivre.utils
import ivre.target
import ivre.nmapopt


if sys.version_info >= (2, 7):
    import functools
    USE_PARTIAL = True
else:
    # Python version <= 2.6:
    # see http://bugs.python.org/issue5228
    # multiprocessing not compatible with functools.partial
    USE_PARTIAL = False
    # Also Python version <= 2.6: cannot use a function defined in
    # another function in a multiprocessing.Pool.imap()
    def _call_nmap_single_tuple(args):
        return _call_nmap_single(*args)


STATUS_NEW = 0
STATUS_DONE_UP = 1
STATUS_DONE_DOWN = 2
STATUS_DONE_UNKNOWN = 3

NMAP_LIMITS = {}


def setnmaplimits():
    """Enforces limits from NMAP_LIMITS global variable."""
    for limit, value in viewitems(NMAP_LIMITS):
        resource.setrlimit(limit, value)


class XmlProcess(object):
    addrrec = re.compile(b'<address\\s+addr="([0-9\\.]+)" addrtype="ipv4"/>')

    def target_status(self, _):
        return STATUS_NEW


class XmlProcessTest(XmlProcess):

    def process(self, fdesc):
        data = fdesc.read()
        if not data:
            return False
        for addr in self.addrrec.finditer(data):
            print("Read address", addr.groups()[0].decode())
        return True


class XmlProcessWritefile(XmlProcess):
    statusline = re.compile(b'<task(begin|end|progress).*/>\n')
    status_up = b'<status state="up"'
    status_down = b'<status state="down"'
    hostbegin = re.compile(b'<host[\\s>]')
    status_paths = {
        'up': STATUS_DONE_UP,
        'down': STATUS_DONE_DOWN,
        'unknown': STATUS_DONE_UNKNOWN,
    }

    def __init__(self, path, fulloutput=False):
        self.path = path
        self.starttime = int(time.time() * 1000000)
        self.data = b''
        self.isstarting = True
        self.startinfo = b''
        ivre.utils.makedirs(self.path)
        self.scaninfo = open('%sscaninfo.%d' % (self.path,
                                                self.starttime),
                             'wb')
        if fulloutput:
            self.has_fulloutput = True
            self.fulloutput = open('%sfulloutput.%d' % (self.path,
                                                        self.starttime),
                                   'wb')
        else:
            self.has_fulloutput = False

    def process(self, fdesc):
        newdata = fdesc.read()
        # print("READ", len(newdata), "bytes")
        if not newdata:
            self.scaninfo.write(self.data)
            self.scaninfo.close()
            if self.has_fulloutput:
                self.fulloutput.close()
            return False
        if self.has_fulloutput:
            self.fulloutput.write(newdata)
            self.fulloutput.flush()
        self.data += newdata
        while b'</host>' in self.data:
            hostbeginindex = self.data.index(
                self.hostbegin.search(self.data).group())
            self.scaninfo.write(self.data[:hostbeginindex])
            self.scaninfo.flush()
            if self.isstarting:
                self.startinfo += self.statusline.sub(
                    b'', self.data[:hostbeginindex],
                )
                self.isstarting = False
            self.data = self.data[hostbeginindex:]
            hostrec = self.data[:self.data.index(b'</host>') + 7]
            try:
                addr = self.addrrec.search(hostrec).groups()[0]
            except Exception:
                ivre.utils.LOGGER.warning("Exception for record %r", hostrec,
                                          exc_info=True)
            if self.status_up in hostrec:
                status = 'up'
            elif self.status_down in hostrec:
                status = 'down'
            else:
                status = 'unknown'
            outfile = self.path + status + \
                '/' + addr.decode().replace('.', '/') + '.xml'
            ivre.utils.makedirs(os.path.dirname(outfile))
            with open(outfile, 'wb') as out:
                # out.write(b'<scaninfo starttime="%d" />\n' % starttime)
                out.write(self.startinfo)
                out.write(hostrec)
                out.write(b'\n</nmaprun>\n')
            self.data = self.data[self.data.index(b'</host>') + 7:]
            if self.data.startswith(b'\n'):
                self.data = self.data[1:]
        return True

    def target_status(self, target):
        for status, statuscode in viewitems(self.status_paths):
            try:
                os.stat(os.path.join(self.path, status,
                                     target.replace('.', '/') + '.xml'))
                return statuscode
            except OSError:
                pass
        return STATUS_NEW


def restore_echo():
    """Hack for https://stackoverflow.com/questions/6488275 equivalent
    issue with Nmap (from
    http://stackoverflow.com/a/8758047/3223422)

    """
    try:
        fdesc = sys.stdin.fileno()
    except ValueError:
        return
    try:
        attrs = termios.tcgetattr(fdesc)
    except termios.error:
        return
    attrs[3] = attrs[3] | termios.ECHO
    termios.tcsetattr(fdesc, termios.TCSADRAIN, attrs)


def call_nmap(options, xmlprocess, targets,
              accept_target_status=None):
    if accept_target_status is None:
        accept_target_status = [STATUS_NEW]
    # "-oX -" 输出XML格式结果, 只输出到标准输出
    # "-iL -" 输入一系列目标, 标准输入
    options += ['-oX', '-', '-iL', '-']
    proc = subprocess.Popen(options, preexec_fn=setnmaplimits,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    procout = proc.stdout.fileno()
    procoutfl = fcntl.fcntl(procout, fcntl.F_GETFL)
    # 设置为非阻塞
    fcntl.fcntl(procout, fcntl.F_SETFL, procoutfl | os.O_NONBLOCK)
    toread = [proc.stdout]
    towrite = [proc.stdin]
    targiter = targets.__iter__()
    while toread:
        # print("ENTERING SELECT")
        # io 多路复用select
        rlist, wlist = select.select(toread, towrite, [])[:2]
        # print("LEAVING SELECT", rlist, wlist)
        for rfdesc in rlist:
            # print("PROCESSING DATA")
            if not xmlprocess.process(rfdesc):
                print("NO MORE DATA TO PROCESS")
                rfdesc.close()
                toread.remove(rfdesc)
        for wfdesc in wlist:
            try:
                naddr = ivre.utils.int2ip(next(targiter))
                # 根据accpt策略，判断是否重复扫描 
                while xmlprocess.target_status(
                        naddr) not in accept_target_status:
                    naddr = ivre.utils.int2ip(next(targiter))
                print("ADDING TARGET", end=' ')
                print(targiter.nextcount, end=' ')
                if hasattr(targets, "targetcount"):
                    print('/', targets.targetscount, end=' ')
                print(":", naddr)
                wfdesc.write(naddr.encode() + b'\n')
                wfdesc.flush()
            except StopIteration:
                print("WROTE ALL TARGETS")
                wfdesc.close()
                towrite.remove(wfdesc)
            except IOError:
                print("ERROR: NMAP PROCESS IS DEAD")
                return -1
    # 等待子进程完成
    proc.wait()
    return 0


def _call_nmap_single(maincategory, options,
                      accept_target_status, target):
    target = ivre.utils.int2ip(target)
    outfile = 'scans/%s/%%s/%s.xml' % (maincategory, target.replace('.', '/'))
    # 根据accept_target_status状态策略决定是否覆盖继续扫描并覆盖已有结果文件
    # accept_target_status默认为set(STATUS_NEW), 即不覆盖任何已有结果文件
    if STATUS_DONE_UP not in accept_target_status:
        try:
            # 这里使用os.stat 函数检查文件是否存在
            # os.path中检查文件或文件夹是否存在的系列函数(isfile, isdir, exists等)
            # 里面都是调用os.stat以及结合其他属性来判断的
            os.stat(outfile % 'up')
            return
        except OSError:
            pass
    if STATUS_DONE_DOWN not in accept_target_status:
        try:
            os.stat(outfile % 'down')
            return
        except OSError:
            pass
    if STATUS_DONE_UNKNOWN not in accept_target_status:
        try:
            os.stat(outfile % 'unknown')
            return
        except OSError:
            pass
    ivre.utils.makedirs(os.path.dirname(outfile % 'current'))
    # 命令行调用， 结果保存在outfile ===================
    # 对比 call_nmap函数使用Popen函数，这里是直接命令行存本地文件，无需使用Popen
    subprocess.call(options + ['-oX', outfile % 'current', target],
                    preexec_fn=setnmaplimits)
    # 根据返回的扫描结果状态移动到相应路径
    resdata = open(outfile % 'current', 'rb').read()
    if b'<status state="up"' in resdata:
        outdir = 'up'
    elif b'<status state="down"' in resdata:
        outdir = 'down'
    else:
        outdir = 'unknown'
    ivre.utils.makedirs(os.path.dirname(outfile % outdir))
    shutil.move(outfile % 'current', outfile % outdir)


def main():
    atexit.register(restore_echo)
    accept_target_status = set([STATUS_NEW])
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Run massive nmap scans.',
            parents=[ivre.target.argparser,
                     ivre.nmapopt.argparser])
        using_argparse = True
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Run massive nmap scans.')
        for parent in [ivre.target.argparser, ivre.nmapopt.argparser]:
            for args, kargs in parent.args:
                parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
        using_argparse = False
    parser.add_argument('--output',
                        choices=['XML', 'XMLFull', 'XMLFork', 'Test',
                                 'Count', 'List', 'ListAll',
                                 'ListAllRand', 'ListCIDRs',
                                 'CommandLine', 'Agent'],
                        default='XML',
                        help='select output method for scan results')
    parser.add_argument('--processes', metavar='COUNT', type=int, default=30,
                        help='run COUNT nmap processes in parallel '
                        '(when --output=XMLFork)')
    parser.add_argument('--nmap-max-cpu', metavar='TIME', type=int,
                        help='maximum amount of CPU time (in seconds) '
                        'per nmap process')
    parser.add_argument('--nmap-max-heap-size', metavar='SIZE', type=int,
                        help="maximum size (in bytes) of each nmap "
                        "process's heap")
    parser.add_argument('--nmap-max-stack-size', metavar='SIZE', type=int,
                        help="maximum size (in bytes) of each nmap "
                        "process's stack")
    # 重复扫描策略 =============================
    if using_argparse:
        parser.add_argument('--again', nargs='+',
                            choices=['up', 'down', 'unknown', 'all'],
                            help='select status of targets to scan again')
    else:
        parser.add_argument('--again',
                            choices=['up', 'down', 'unknown', 'all'],
                            help='select status of targets to scan again')
    args = parser.parse_args()
    if args.output == 'CommandLine':
        print("Command line to run a scan with template "
              "%s" % args.nmap_template)
        print("    %s" % ivre.nmapopt.build_nmap_commandline(
            template=args.nmap_template,
        ))
        exit(0)
    if args.output == 'Agent':
        sys.stdout.write(ivre.agent.build_agent(template=args.nmap_template))
        exit(0)
    if args.output == 'Count':
        if args.country is not None:
            print('%s has %d IPs.' % (
                args.country,
                ivre.geoiputils.count_ips_by_country(args.country)
            ))
            exit(0)
        if args.region is not None:
            print('%s / %s has %d IPs.' % (
                args.region[0], args.region[1],
                ivre.geoiputils.count_ips_by_region(*args.region),
            ))
            exit(0)
        if args.city is not None:
            print('%s / %s has %d IPs.' % (
                args.city[0], args.city[1],
                ivre.geoiputils.count_ips_by_city(*args.city),
            ))
            exit(0)
        if args.asnum is not None:
            print('AS%d has %d IPs.' % (
                args.asnum,
                ivre.geoiputils.count_ips_by_asnum(args.asnum)
            ))
            exit(0)
        if args.routable:
            print('We have %d routable IPs.' % (
                ivre.geoiputils.count_routable_ips()
            ))
            exit(0)
        parser.error("argument --output: invalid choice: '%s' "
                     "(only available with --country, --asnum, --region, "
                     "--city or --routable)" % args.output)
    if args.output in ['List', 'ListAll', 'ListCIDRs']:
        if args.country is not None:
            ivre.geoiputils.list_ips_by_country(
                args.country, listall=args.output == 'ListAll',
                listcidrs=args.output == 'ListCIDRs',
            )
            exit(0)
        if args.region is not None:
            ivre.geoiputils.list_ips_by_region(
                *args.region,
                listall=args.output == 'ListAll',
                listcidrs=args.output == 'ListCIDRs'
            )
            exit(0)
        if args.city is not None:
            ivre.geoiputils.list_ips_by_city(
                *args.city,
                listall=args.output == 'ListAll',
                listcidrs=args.output == 'ListCIDRs'
            )
            exit(0)
        if args.asnum is not None:
            ivre.geoiputils.list_ips_by_asnum(
                args.asnum, listall=args.output == 'ListAll',
                listcidrs=args.output == 'ListCIDRs',
            )
            exit(0)
        if args.routable:
            ivre.geoiputils.list_routable_ips(
                listall=args.output == 'ListAll',
                listcidrs=args.output == 'ListCIDRs',
            )
            exit(0)
        parser.error("argument --output: invalid choice: '%s' "
                     "(only available with --country, --region, --city, "
                     "--asnum or --routable)" % args.output)
    
    # 目标解析 ========================
    targets = ivre.target.target_from_args(args)
    if targets is None:
        parser.error('one argument of --country/--region/--city/--asnum/'
                     '--range/--network/--routable/--file/--test is required')
    if args.again is not None:
        accept_target_status = set(reduce(
            lambda x, y: x + y, [{
                'up': [STATUS_DONE_UP],
                'down': [STATUS_DONE_DOWN],
                'unknown': [STATUS_DONE_UNKNOWN],
                'all': [STATUS_DONE_UP, STATUS_DONE_DOWN,
                        STATUS_DONE_UNKNOWN]
            }[x] for x in args.again],
            [STATUS_NEW]))
    if args.zmap_prescan_port is not None:
        args.nmap_ping_types = ["PS%d" % args.zmap_prescan_port]
    # nmap 预扫描
    elif args.nmap_prescan_ports is not None:
        args.nmap_ping_types = [
            "PS%s" % ",".join(str(p) for p in args.nmap_prescan_ports)
        ]
    # namp选项构建    
    options = ivre.nmapopt.build_nmap_options(template=args.nmap_template)

    # 资源限制
    if args.nmap_max_cpu is not None:
        NMAP_LIMITS[resource.RLIMIT_CPU] = (args.nmap_max_cpu,
                                            args.nmap_max_cpu)
    if args.nmap_max_heap_size is not None:
        NMAP_LIMITS[resource.RLIMIT_DATA] = (args.nmap_max_heap_size,
                                             args.nmap_max_heap_size)
    if args.nmap_max_stack_size is not None:
        NMAP_LIMITS[resource.RLIMIT_STACK] = (args.nmap_max_stack_size,
                                              args.nmap_max_stack_size)
    # 多进程支持
    if args.output == 'XMLFork':
        pool = multiprocessing.Pool(processes=args.processes)
        if USE_PARTIAL:
            call_nmap_single = functools.partial(_call_nmap_single,
                                                 targets.infos[
                                                     'categories'][0],
                                                 options,
                                                 accept_target_status)
            for _ in pool.imap(call_nmap_single, targets, chunksize=1):
                pass
        else:
            for _ in pool.imap(_call_nmap_single_tuple,
                               ((targets.infos['categories'][0],
                                 options,
                                 accept_target_status,
                                 target) for target in targets),
                                chunksize=1):
                pass
        exit(0)
    elif args.output == 'ListAllRand':
        targiter = targets.__iter__()
        try:
            for target in targiter:
                print(ivre.utils.int2ip(target))
        except KeyboardInterrupt:
            print('Interrupted.\nUse "--state %s" to resume.' % (
                ' '.join(str(elt) for elt in targiter.getstate())
            ))
        except Exception:
            ivre.utils.LOGGER.critical('Exception', exc_info=True)
            print('Use "--state %s" to resume.' % (
                ' '.join(str(elt) for elt in targiter.getstate())
            ))
        exit(0)
    # pythonic ++++++++++++++++++++++++++++++
    xmlprocess = {
        'XML': (XmlProcessWritefile,
                ['./scans/%s/' % targets.infos['categories'][0]], {}),
        'XMLFull': (XmlProcessWritefile,
                    ['./scans/%s/' % targets.infos['categories'][0]],
                    {'fulloutput': True}),
        'Test': (XmlProcessTest, [], {}),
    }[args.output]
    xmlprocess = xmlprocess[0](*xmlprocess[1], **xmlprocess[2])
    retval = call_nmap(options, xmlprocess, targets,
                       accept_target_status=accept_target_status)
    exit(retval)
