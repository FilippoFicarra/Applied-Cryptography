#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50402)

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
        'command' : 'flag',
    }
    json_send(request)

    response = json_recv()
    # print(response)
    

    flag_m0 = response["m0"]
    flag_c0 = response["c0"]
    flag_ctxt = response["ctxt"]

    # print(f"m0: {flag_m0}, c0: {flag_c0}, ctxt: {flag_ctxt}")
    
    request = {
        'command' : 'decrypt',
        'm0' : flag_m0,
        'c0' : flag_c0,
        'ctxt' : flag_ctxt[:len(flag_ctxt)-1]+"00",
    }

    json_send(request)

    response = json_recv()

    print(response)

    # request = {
    #     'command' : 'decrypt',
    #     'ctxt' : flag_ctxt,
    #     'm0' : flag_m0,
    #     'c0' : flag_c0,
    # }
    # json_send(request)

    # response = json_recv()

    # print(response)

    # return response["res"]

if __name__ == "__main__":
    flag = solve()
    # print(flag)
    



