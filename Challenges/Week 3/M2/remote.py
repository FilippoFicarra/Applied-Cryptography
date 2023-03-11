#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad


tn = telnetlib.Telnet("aclabs.ethz.ch", 50302)

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

c = b''
for i in range(2**128):
    request = {
        'command': 'encrypted_command', 
        'encrypted_command': i.to_bytes(16, "big").hex()
    }
    json_send(request)

    response = json_recv()
    if "No such command: " in response["res"]:
        p = bytes.fromhex(response["res"][17:])
        c = i.to_bytes(16, "big")
        break
r = byte_xor(c,pad(p,16))

c_prime = byte_xor(pad(b'flag',16),r)

request = {
        'command': 'encrypted_command', 
        'encrypted_command': c_prime.hex()
    }
json_send(request)

response = json_recv()
print(response)
