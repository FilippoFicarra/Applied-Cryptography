#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "aclabs.ethz.ch"
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

# for i in range(300):
    # for j in range(255):
for i in range(300):
    guess = True
    request = {
        'command': 'decrypt', 
        'ciphertext': int.to_bytes(i, 16, "big").hex()
    }
    json_send(request)

    response = json_recv()
    print(response["res"].encode())
    print(len(response["res"].encode()))
    if len(response["res"].encode()) == 32:
        guess = False
    print(guess)
    request = {
        'command': 'guess', 
        'guess': guess
    }
    json_send(request)
    response = json_recv()
    print(response)
            
request = {
    'command': 'flag', 
}
json_send(request)
response = json_recv()
print(response)

