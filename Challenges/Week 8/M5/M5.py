from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json


server = "localhost"#"aclabs.ethz.ch"
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
   
    request = {
        'command': 'pub_key', 
    }
    json_send(request)

    response = json_recv()
    print(response)

    N = int(response['N'], 16)

    es = []
    ctxts = []
    count = 0
    while True:

        e = number.getPrime(10)

        request = {
            'command': 'encrypt', 
            'e': e
        }
        json_send(request)
        response = json_recv()

        if 'ciphertext' in response :
            if e not in es:
                count += 1
                es.append(e)
                ctxts.append(int(response['ciphertext'], 16))
                if count > 1:
                    break

    # print(es)
    # print(ctxts)
    print(math.gcd(es[0], N))
    gcd, x, y = extended_euclidean_algorithm(es[0], es[1])

    # print(gcd)
    # print(x)
    # print(y)


    return  True



if __name__ == "__main__":

    print(solve())
    