#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50342)

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

for i in range(10):
    request = {
        'command': 'challenge',
    }
    json_send(request)

    response = json_recv()
    challenge = bytes.fromhex(response["res"])

    blocks = [challenge[i:i+16] for i in range(0,len(challenge),16)]
    l = len(blocks)

    a = blocks[l-2]
    found = b''
    for j in range(1,17):
        found = byte_xor(byte_xor(found, (j-1).to_bytes(1, "big")*(j-1)),j.to_bytes(1,"big")*(j-1))
        b = blocks[l-2][:16-j] if 16-j > 0 else b''
        for i in range(255):
            blocks[l-2] = (b + i.to_bytes(1, "big") + found)[:16]
            
            request = {
                'command': 'decrypt', 
                'ciphertext': b''.join(blocks).hex()
            }
            json_send(request)

            response = json_recv()
            
            if len(response["res"]) == 64:
                found = blocks[l-2][-j:]
                break
    try:
        message = byte_xor(byte_xor(blocks[l-2], int.to_bytes(16,1,"big")*16),a).decode()
    except:
        message = unpad(byte_xor(byte_xor(blocks[l-2], int.to_bytes(16,1,"big")*16),a),16).decode()
    
    request = {
        'command': 'guess', 
        'guess': message
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

