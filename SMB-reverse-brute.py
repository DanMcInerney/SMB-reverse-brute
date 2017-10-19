#!/usr/bin/env python3
import sys
import os
import time
import asyncio
import argparse
import functools
from itertools import zip_longest
from libnmap.process import NmapProcess
#from subprocess import Popen, STDOUT, PIPE
from asyncio.subprocess import PIPE, STDOUT
from libnmap.parser import NmapParser, NmapParserException
from IPython import embed

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-x", "--xml", help="path to nmap XML file")
    return parser.parse_args()

def parse_nmap(args):
    '''
    Either performs an nmap scan or parses an nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.xml:
        report = NmapParser.parse_fromfile(args.xml)
    elif args.hostlist:
        with open(args.hostlist, 'r') as hostlist:
            hosts = hostlist.read().split()
        report = nmap_scan(hosts)
    else:
        print('Use the "-x [path/to/nmap-output.xml]" option if you already have an nmap XML file \
or "-l [hostlist.txt]" option to run an nmap scan with a hostlist file.')
        sys.exit()
    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    # This is top 1000 tcp + top 50 UDP scan
    # Nmap has chosen not to do --top-udp/tcp-ports options due to not wanting to overcomplicate
    # the cmd line interface
    nmap_args = '-sS -n -v --reason --max-retries 5 -p 445 -oA SMB-reverse-brute-nmap'
    print('[*] Running nmap')
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/SMB-reverse-brute-nmap.xml')

    return report

def nmap_status_printer(nmap_proc):
    '''
    Prints that Nmap is running
    '''
    while nmap_proc.is_running():
        print("[*] Nmap running...")
        time.sleep(1)


def get_hosts(report):
    '''
    Gets list of hosts with port 445 open
    '''
    hosts = []

    for host in report.hosts:
        if host.is_up():
            for s in host.services:
                if s.port == 445:
                    if s.state == 'open':
                        ip = host.address
                        print('[+] SMB open: {}'.format(ip))
                        hosts.append(ip)
    if len(hosts) == 0:
        sys.exit('[-] No hosts were found with port 445 open')
    print()
    return hosts

def async_get_outputs(commands):
    '''
    Asynchronously run commands and get get their output in a list
    '''
    loop = asyncio.get_event_loop()
    # get commands output in parallel
    worker_count = len(commands) - 1
    if worker_count > 10:
        worker_count = 10

    coros = [get_output(cmd) for cmd in commands for i in range(worker_count)]
    output = loop.run_until_complete(asyncio.gather(*coros))
    loop.close()
    #flattened_output = [out for sublist in output for out in sublist]
    return output

def create_cmds(hosts, cmd):
    '''
    Creates the list of comands to run
    cmd looks likes "echo {} && rpcclient ... {}"
    '''
    commands = []
    for ip in hosts:
        # first ip is for echo, second is for rpcclient
        formatted_cmd = cmd.format(ip, ip)
        commands.append(formatted_cmd)
    return commands

#def async_run_cmds(hosts, cmd):
#
#    # output is a list of rpcclient output
#    output = async_get_cmd_outputs(commands)
#    for out in output:
#        out = out.decode('utf8')
#        out = out.splitlines()
#        ip = out[0]


def get_null_sess_hosts(output):
    '''
    Gets a list of all hosts vulnerable to SMB null sessions
    '''
    null_sess_hosts = {}
    # output is a list of rpcclient output
    for out in output:
        if 'Domain Name:' in out:
            out = out.splitlines()
            ip = out[0]
            dom = out[1]
            dom_sid = out[2]
            null_sess_hosts[ip] = (dom, dom_sid)
    return null_sess_hosts

def print_domains(null_sess_hosts):
    '''
    Prints the unique domains
    '''
    uniq_doms = []
    for key,val in null_sess_hosts.items():
        dom_name = val[0]
        if dom_name not in uniq_doms:
            dom = dom_name.split()[2]
            uniq_doms.append(dom)

    if len(uniq_doms) > 0:
        print('[+] Domains found')
        for d in uniq_doms:
            print('      {}'.format(d)) 
    print()

@asyncio.coroutine
def get_output(cmd):
    '''
    Performs async OS commands
    '''
    p = yield from asyncio.create_subprocess_shell(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    # Output returns in byte string so we decode to utf8
    return (yield from p.communicate())[0].decode('utf8')


def main(report, args):

    null_sess_hosts = {}
    # get_hosts will exit script if no hosts are found
    hosts = get_hosts(report)
    # echo is necessary because async.gather() only takes
    # a list of coroutines and spits out their output in 
    # fastest order so you lose the attachment of the ip
    # to the output of the command
    cmd = 'echo {} && rpcclient -U "" {} -N -c "lsaquery"'
    cmds = create_cmds(hosts, cmd)
    rpc_output = async_get_outputs(cmds)
    # Returns all null sess cmd outputs up to worker number
    # {ip:'domain name: xxx', 'domain sid: xxx'}
    chunk_null_sess_hosts = get_null_sess_hosts(rpc_output)
    # Create master list of null session hosts
    null_sess_hosts.update(chunk_null_sess_hosts)
    print_domains(null_sess_hosts)

    cmd = 'echo {} && python3 ridenum {} 500 50000"'
    cmds = create_cmds(hosts, cmd)
    ridenum_output = async_get_outputs(cmds)
    print ridenum_output
    # {ip:[list of recovered usernames]}

    #ip_usernames = get_usernames(null_sess_hosts)



if __name__ == "__main__":

    args = parse_args()
    if os.geteuid():
        exit('[-] Run as root')
    report = parse_nmap(args)

    main(report, args)
