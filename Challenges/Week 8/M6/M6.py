from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json
import datetime

import numpy


server = "localhost"#"aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50806)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def extended_euclidean_algorithm(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        gcd, x, y = extended_euclidean_algorithm(b, a % b)
        return (gcd, y, x - (a // b) * y)

def chinese_remainder(moduli , rem) : 
    # Compute product of all numbers 
    prod = 1
    for i in range(0, len(moduli)) : 
        prod = prod * moduli[i] 
  
    # Initialize result 
    result = 0
  
    # Apply above formula 
    for i in range(0,len(moduli)): 
        pp = prod // moduli[i] 
        result = result + rem[i] * number.inverse(pp, moduli[i]) * pp 
      
    return result % prod



def solve():
   
    Ns = []
    es = []

    for i in range(10):
        request = {
            'command': 'generate', 
        }
        json_send(request)

        response = json_recv()
        print(response)
        # t = datetime.datetime.now().second
        # print(t)

    return  True



if __name__ == "__main__":

    print(solve())
    