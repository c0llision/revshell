#!/usr/bin/env python3

from revshell import *

print(is_valid_ip("0.0.0.0"))
print(is_valid_ip("255.255.255.255"))
print(is_valid_ip("8.8.8.8"))

print(is_valid_ip("8.8.8.8.8"))
print(is_valid_ip("abc.abc.abc.abc"))
print(is_valid_ip("abc"))
print(is_valid_ip("8..8.8.8.8"))
print(is_valid_ip("-1.255.255.255"))
print(is_valid_ip("8888"))

