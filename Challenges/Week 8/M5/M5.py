from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json


server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50805)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def extended_euclidean_algorithm(a, b):
    # Base Case
    if a == 0 :
        return b,0,1
             
    gcd,x1,y1 = extended_euclidean_algorithm(b%a, a)
     
    # Update x and y using results of recursive
    # call
    x = y1 - (b//a) * x1
    y = x1
     
    return gcd,x,y

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
   
    request = {
        'command': 'pub_key', 
    }
    json_send(request)

    response = json_recv()

    N = int(response['N'], 16)

    count = 0
    es = []
    ctxts = []
    while True:
        e = number.getPrime(10)

        request = {
            'command': 'encrypt', 
            'e': e
        }
        json_send(request)
        response = json_recv()

        if 'ciphertext' in response :
            ctxt = int(response['ciphertext'], 16)
            
            es.append(e)
            ctxts.append(ctxt)
            count += 1 
            if count == 2:
                break

    
    gcd, x, y = extended_euclidean_algorithm(es[0], es[1])
    m = pow(ctxts[0], x, N) * pow(ctxts[1], y, N) % N


    return  m.to_bytes(128, 'big').decode()



if __name__ == "__main__":

    print(solve())
    