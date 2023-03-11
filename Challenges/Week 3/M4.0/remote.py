#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "localhost" #"aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50340)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def byte_xor(ba1, ba2):
            return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# print(pad(b'message',16)[:-1])

for i in range(300):
    for j in range(255):

        request = {
            'command': 'decrypt', 
            'encrypted_command': (pad(b'message', 16)[:-1]+j.to_bytes(1, "big")).hex()
        }
        json_send(request)

        response = json_recv()

        print(response)
    break
