#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50401)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def solve():

    request = {
        'command' : 'register',
        'username' : '0000000username=000000000000&role=admin',
        'favourite_coffee' : 'Cappuccino000000'
    }
    json_send(request)

    response = json_recv()

    token = response["token"][32:]
    
    request = {
        'command' : 'login',
        'token' : token,
    }
    json_send(request)

    response = json_recv()

    request = {
        'command' : 'change_settings',
        'good_coffee' : "true"
    }
    json_send(request)

    response = json_recv()

    request = {
        'command' : 'get_coffee',
    }
    json_send(request)

    response = json_recv()

    return response["res"]

if __name__ == "__main__":
    flag = solve()
    print(flag)
    



