import telnetlib
import json
from passlib.hash import argon2

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50501)


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
        'command' : 'password',
    }
    json_send(request)

    response = json_recv()
    password = response["res"]
    request = {
        'command' : 'guess',
        'guess' : argon2.hash(bytes.fromhex(password))
    }
    json_send(request)

    response = json_recv()
    return response["res"]

if __name__ == "__main__":

    flag = solve()
    print(flag)
    



