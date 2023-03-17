#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "localhost" #"aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50400)

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

def solve():
    for i in range(2):
        request = {
            'command' : 'query',
            'm' : (i.to_bytes(1, "big")*16).hex()
        }
        json_send(request)

        response = json_recv()

        print(response)

# request = {
#     'command' : 'encrypted_command',
#     'encrypted_command' : response["res"]
# }
# json_send(request)

# response = json_recv()

if __name__ == "__main__":
    flag = solve()
    



