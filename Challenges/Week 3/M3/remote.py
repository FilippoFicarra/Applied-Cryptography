#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad


tn = telnetlib.Telnet("aclabs.ethz.ch", 50303)

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
c = "a4e96965c88255d3f5454928e72ce8ac89d99bff2db6caf43a9903b50e1ca525"

iv = c[:32]
iv_1 = byte_xor(byte_xor(bytes.fromhex(iv), pad(b'intro',16)), pad(b'flag',16)).hex()
c_intro = c[32:]
print(iv)
request = {
    'command': 'encrypted_command', 
    'encrypted_command': bytes.fromhex(iv_1+c_intro).hex()
}
json_send(request)

response = json_recv()

print(response)
