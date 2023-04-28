from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50802)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def cubic_root_int(a, x_0 = 1, tol=1e-10) -> int:

    x_n = x_0
    while True:
        x_n1 = (2*x_n + a//(x_n*x_n))//3
        if abs(x_n1 - x_n) < tol:
            return x_n1
        x_n = x_n1



def solve():
    request = {
        'command': 'encrypted_flag', 
    }
    json_send(request)

    response = json_recv()
    print(response)
    ctxt = int(response['ctxt'])
    N = int(response['N'])
    e = int(response['e'])

    m = int(cubic_root_int(ctxt))

    return m.to_bytes(4096, 'big').decode()



if __name__ == "__main__":

    print(solve())
    