import secrets
from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import mpmath
import gmpy2

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50803)

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

def nextPrime( p: int):
    while True:
        p = p + 2
        if number.isPrime(p):
            return p

def solve():
    request = {
        'command': 'encrypted_flag', 
    }
    json_send(request)
   
    response = json_recv() 
    
    gmpy2.get_context().precision = 10000


    i = 1
    ctxt = response['ctxt']
    N = int(response['N'])
    e = int(response['e'])
    while True:
        delta = int(math.ceil(gmpy2.root(i**2 + N,2)))
        if (delta**2 == (i**2 + N)):
            p = delta - i
            q = p + i*2
            break
        i += 1

    phiN = (p-1)*(q-1)
    d = number.inverse(e, phiN)
    key = RSA.construct((N, e, d))
    cipher = PKCS1_OAEP.new(key)
    print(cipher.decrypt(bytes.fromhex(ctxt)).decode())


if __name__ == "__main__":

    solve()
    