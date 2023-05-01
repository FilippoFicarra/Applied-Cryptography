#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import secrets
import telnetlib
import json
from M6.M6 import CBC_HMAC

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
    key = secrets.token_bytes(56)
    aead = CBC_HMAC(32, 24, key) # key is random, we just need the padding function
    request = {
        'command': 'get_token', 
    }
    json_send(request)

    response = json_recv()
    guest_token = bytes.fromhex(response['guest token'])
    message = aead._add_pt_padding(b'admin')
    old_message = aead._add_pt_padding(b'guest')

    print(guest_token.hex())
    iv  = guest_token[:16]
    ct = guest_token[16:32]
    tag = guest_token[32:]

    iv_p = byte_xor(byte_xor(message, iv), old_message)

    new_ct = iv_p + ct

    # now we need to forge the tag

    request = {
        'command': 'rekey', 
        'key': key.hex()
    }
    json_send(request)

    response = json_recv()
    print(response)

    # request = {
    #     'command': 'authenticate', 
    #     'token': guest_token.hex()
    # }
    # json_send(request)

    # response = json_recv()
    # print(response)


    # request = {
    #     'command': 'show_state', 
    #     'prefix': b'Fulippo'.hex()
    # }
    # json_send(request)

    # response = json_recv()
    # print(response)



if __name__ == "__main__":
    solve()
            


