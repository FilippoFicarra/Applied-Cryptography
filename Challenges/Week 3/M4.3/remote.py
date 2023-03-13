#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad
import time
from string import ascii_letters, digits, punctuation

ALPHABET = ascii_letters + digits + punctuation
printable_chars = bytes(ALPHABET, 'ascii')
for i in range(1,17):
     printable_chars += i.to_bytes(1,"big")


server = "localhost" #"aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50343)

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

def block_crack(full_message_blocks, l):
    found  = b''
    a = full_message_blocks[l]
    for j in range(1,17):
        found = byte_xor(byte_xor(found, (j-1).to_bytes(1, "big")*(j-1)),j.to_bytes(1,"big")*(j-1))
        b = full_message_blocks[l][:16-j] if 16-j > 0 else b''
        for i in range(256):
            full_message_blocks[l] = (b + i.to_bytes(1, "big") + found)[:16]
            
            request = {
                'command' : 'encrypted_command', 
                'encrypted_command': b''.join(full_message_blocks).hex() 
            }
            json_send(request)

            response = json_recv()
            k = len(bytes.fromhex(response["res"]))

            if k == 96 and k != 144 and k != 128 :
                found = full_message_blocks[l][-j:]
                g = byte_xor(byte_xor(found, int.to_bytes(j,1,"big")*j),a[-j:])
                print(g)

            
    message = byte_xor(byte_xor(full_message_blocks[l], int.to_bytes(16,1,"big")*16),a)

    full_message_blocks[l] = a
    return message
         

def get_challenge():
    challenge = ''

    for i in range(256):
        request = {
            'command' : 'encrypted_command',
            'encrypted_command' : i.to_bytes(32, "big").hex()
        }
        json_send(request)

        response = json_recv()
        k = len(bytes.fromhex(response["res"]))
        if k == 96 and k != 144 and k != 128 :
            challenge = response["res"]
            print("Challenge : ", challenge,  len(challenge)/2)
            
            
    challenge = bytes.fromhex(challenge)
    return challenge


challenge = get_challenge()
blocks = [challenge[i:i+16] for i in range(0,len(challenge),16)]
l = len(blocks)
message = []
m = b''
for i in range(l-2, -1, -1):
    crack = block_crack(blocks[:i+2], i)
    print(crack)
    message.append(crack)
    
    

print("RESULT : ")
print(message)
try:
    print(unpad(b"".join(reversed(message)),16))
except:
     print(b"".join(reversed(message)))


