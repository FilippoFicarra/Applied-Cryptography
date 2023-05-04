#!/usr/bin/env python3

import telnetlib
import json
import itertools
from string import ascii_letters, digits, punctuation
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad




ALPHABET = ascii_letters + digits + punctuation


tn = telnetlib.Telnet("aclabs.ethz.ch", 50604)


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

    ctxt_f = response["ctxt"]
    nonce_f = response["nonce"]
    mac_tag_f = response["mac_tag"]

    print(ctxt_f)
    print(nonce_f)
    print(mac_tag_f)

    

    flag = ''
    for i in range(0, len(ctxt_f)//2):
        letter_tag = {}

        for letter in ALPHABET:
            request = {
                "command": "encrypt",
                "ptxt": flag + letter
            }
            json_send(request)
            response = json_recv()

            ctxt = response["enc_flag"]
            nonce = response["nonce"]
            mac_tag = response["mac_tag"]

            letter_tag[flag + letter] = {
                    "nonce" : nonce,
                    "mac_tag" : mac_tag,
                    "ctxt" : ctxt
                }
            
        for keys in list(letter_tag.keys()):
            print(keys)
            request = {
                "command": "decrypt",
                "ctxt": ctxt_f[:(i+1)*2],
                "nonce": nonce_f,
                "mac_tag": letter_tag[keys]["mac_tag"]
            }
            json_send(request)
            response = json_recv()

            if response["success"] == True:
                flag = keys
                break
        
    print(flag)


    # message = "A" * (len(ctxt_f)//2)
    # request = {
    #     "command": "encrypt",
    #     "ptxt": message
    # }
    # json_send(request)
    # response = json_recv()

    # ctxt = response["enc_flag"]
    # nonce = response["nonce"]
    # mac_tag = response["mac_tag"]

    # r = byte_xor(message.encode(), bytes.fromhex(ctxt))
    # for i in range(2**12):
    #     request = {
    #         "command": "decrypt",
    #         "ctxt": i.to_bytes(len(ctxt)//2, "big").hex(),# find the right ciphertext with associated nonce to encrypt in the ptxt associated to the mac, then retrieve through r
    #         "nonce": nonce,
    #         "mac_tag": mac_tag
    #     }
    #     json_send(request)
    #     response = json_recv()


    #     if response["success"] == True:
    #         print("success")
    #         ptxt = byte_xor(i.to_bytes(len(ctxt)//2, "big"), r).decode()
    #         return ptxt


if __name__ == "__main__":
    print(solve())
