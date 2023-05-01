#!/usr/bin/env python3

import telnetlib
import json
import itertools
from string import ascii_letters, digits
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad




ALPHABET = ascii_letters + digits


tn = telnetlib.Telnet("aclabs.ethz.ch", 50603)


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
        "command": "challenge",
    }
    json_send(request)
    response = json_recv()

    ctxt = response["res"]
    print(f'ctxt : {ctxt}')

    request = {
        "command": "corrupt",
    }
    json_send(request)
    response = json_recv()["res"]

    k_auth = bytes.fromhex(response.split(':')[1][1:])

    dictionary = {}
    combinations = list(itertools.product(ALPHABET, repeat=4))

    count = 0
    for combination in combinations:
        
        word = ''.join(combination)
        dictionary[HMAC.new(k_auth, word.encode(), SHA256).digest().hex()] = word
        count += 1

    print(f'count : {count}')
        


    for i in range(128):
        print(f'round {i}')
        word = dictionary[ctxt[-64:]]
        print(f'word : {word}')
        request = {
            "command": "guess",
            "guess": word,
        }
        json_send(request)
        response = json_recv()
        
        print(response)
        request = {
            "command": "challenge",
        }
        json_send(request)
        response = json_recv()

        ctxt = response["res"]

    request = {
        "command": "flag",
    }
    json_send(request)
    flag = json_recv()["res"]
    return flag





    


if __name__ == "__main__":
    print(solve())
