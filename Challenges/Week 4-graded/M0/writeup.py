#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

server = "aclabs.ethz.ch"
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
    for i in range(64):
        # ciphers = {}
        # for j in range(10):
        request = {
        'command' : 'query',
        'm' : int.to_bytes(0,16, "big").hex()
        }
        json_send(request)

        response = json_recv()
        cipher = response["res"]

        dic_enc = {}
        dic_dec = {}

        for k in range(2**16):
            lkey = SHA256.new(k.to_bytes(2,"big")).digest()
            lcipher = AES.new(lkey, AES.MODE_ECB)
            dic_enc[k] = lcipher.encrypt(int.to_bytes(0,16, "big"))
        for k in range(2**16):
            rkey = SHA256.new(k.to_bytes(2,"big")).digest()
            rcipher = AES.new(rkey, AES.MODE_ECB)
            dic_dec[k] = rcipher.decrypt(bytes.fromhex(cipher))
        
        s = set(dic_enc.values()).intersection(set(dic_dec.values()))
     
        b = 0 if len(s) != 0 else 1
        request = {
            'command' : 'guess',
            'b' : b
        }

        json_send(request)

        response = json_recv()

    request = {
        'command' : 'flag',
    }

    json_send(request)

    response = json_recv()

    return response["flag"]


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



