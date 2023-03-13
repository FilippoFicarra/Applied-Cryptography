#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50341)

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

for i in range(100):
    request = {
        'command': 'challenge',
    }
    json_send(request)

    response = json_recv()
    challenge = bytes.fromhex(response["res"])

    blocks = [challenge[i:i+16] for i in range(0,len(challenge),16) ]
    l = len(blocks)
    letter = b''
    c = blocks[l-2][15]
    
    for i in range(255):
        blocks[l-2] = blocks[l-2][:15] + i.to_bytes(1, "big")
        
        request = {
            'command': 'decrypt', 
            'ciphertext': (blocks[l-2]+ blocks[l-1]).hex()
        }
        json_send(request)

        response = json_recv()
        # print(response)
        
        if len(response["res"]) == 64:
            letter = byte_xor(byte_xor(int.to_bytes(1, 1, "big"), i.to_bytes(1, "big")),c.to_bytes(1, "big"))
            blocks[l-2] = blocks[l-2][:15] + c.to_bytes(1, "big")
            break
    request = {
        'command': 'guess', 
        'guess': letter.decode()
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

