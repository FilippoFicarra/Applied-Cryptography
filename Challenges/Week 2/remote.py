#!/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50222

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

from Crypto.Util.Padding import pad, unpad

# task M2.0
def solveM20():
    prep = pad("flag, please!".encode("utf-8"), 16).hex()

    request = {
        "command": "encrypt",
        "prepend_pad" : prep,
    }
    json_send(request)

    response = json_recv()

    r1 = response

    request = {
        "command": "solve",
        "ciphertext" : r1["res"][:32]
    }
    json_send(request)

    response = json_recv()
    # if("Nope" not in response["res"]):
    print(response)


# Task M2.1

def enc_req(body : bytes):
    request = {
        "command": "encrypt",
        "prepend_pad" : body.hex(),
    }
    json_send(request)

    return json_recv()

def solveM21():

    for i in range(5):
        z=b""
        print(enc_req(z)["res"])
        
        l = int(len(enc_req(z)["res"]))
        print(l/2)


        for y, _ in enumerate([i for i in range(0, l, 32)]):
            for x in range(15, -1, -1):
                prep = (b"0"*x)
                # print(len(prep)/2)
                r1 = enc_req(prep)
                # print(r1)
                for j in range(256):
                    # print(j)
                    # print(prep + int.to_bytes(j, 1, "big"))
                    r2 = enc_req(prep + z + int.to_bytes(j, 1, "big"))
                    
                    if r2["res"][:y*32+32] == r1["res"][:y*32+32]:
                        z += int.to_bytes(j, 1, "big")
                        print(z)
                        # if(x == 14):
                        #     exit()
                        break
                
        print(enc_req(z)["res"])
        c = z[-2:-1]
        print(c)

        request = {
            "command": "solve",
            "solve" : c.decode("utf-8")
        }
        json_send(request)
        response = json_recv()
        print(response)
        
        
    print(json_recv())
        
solveM21()