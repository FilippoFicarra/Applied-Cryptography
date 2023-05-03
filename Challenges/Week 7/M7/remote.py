#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import secrets
import telnetlib
import json
from M6 import CBC_HMAC

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50707)

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
    request = {
        'command': 'get_token', 
    }
    json_send(request)

    response = json_recv()
    guest_token = bytes.fromhex(response['guest token'])

    print("Guest token : ", guest_token.hex())
    iv  = guest_token[:16]
    ct = guest_token[16:32]
    tag = guest_token[32:]

    count = -1
    while True:
        count += 1
        request = {
            'command': 'rekey', 
            'key': (count.to_bytes(32, "big")+b'\x00'*24).hex() # this is the key we want to xor, the last 24 bytes are 0 so we mantain the tag, and we need to change the encryption key so we can have another message
        }
        json_send(request)

        response = json_recv()
        request = {
            'command': 'authenticate', 
            'token': guest_token.hex()
        }
        json_send(request)

        response = json_recv()
        try:
            res = response["resp"]
            request = {
                'command': 'show_state', 
                'prefix': b'Fulippo'.hex()
            }
            json_send(request)

            response = json_recv()
            try:
                res = response["resp"]
                if "flag" in res:
                    print(res)
                    break
            except:
                continue
        except:
            continue
             


if __name__ == "__main__":
    solve()
            


