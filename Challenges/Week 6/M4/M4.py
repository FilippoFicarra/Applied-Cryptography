#!/usr/bin/env python3

import telnetlib
import json
import itertools
from string import ascii_letters, digits
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad




ALPHABET = ascii_letters + digits


tn = telnetlib.Telnet("aclabs.ethz.ch", 50604)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def blockify(data: bytes, blocksize: int):
    assert(len(data) % blocksize == 0)
    return [int.from_bytes(data[i:i+blocksize], 'big') for i in range(0, len(data), blocksize)]

def left_shift_circular(word: int, shift_amount:int = 1) -> int:
    return ((word << shift_amount) | (word >> (32 - shift_amount))) & 0xffffffff

def solve():
    request = {
        "command": "flag",
    }
    json_send(request)
    response = json_recv()

    ctxt = response["ctxt"]
    nonce = response["nonce"]
    mac_tag = response["mac_tag"]

    print(ctxt)
    print(nonce)
    print(mac_tag)


    request = {
        "command": "encrypt",
        "ptxt": "A" * (len(ctxt)//2)
    }
    json_send(request)
    response = json_recv()

    ctxt = response["enc_flag"]
    nonce = response["nonce"]
    mac_tag = response["mac_tag"]

    print(ctxt)
    print(nonce)
    print(mac_tag)









    


if __name__ == "__main__":
    print(solve())
