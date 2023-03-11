#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50301)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


request = {
    'command': 'encrypted_command', 
    'encrypted_command': '0ef2dba6b9d2feca242e3e30cf94e7eb'
}
json_send(request)

response = json_recv()

print(response)
