from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50801)

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
        'command': 'encrypted_flag', 
    }
    json_send(request)

    response = json_recv()
    print(response)
    encrypted_flag = int(response['encypted_flag'], 16)
    N = int(response['N'], 16)
    e = int(response['e'], 16)

    s = random.randint(1, N-1)
    c = pow(s, e, N) * encrypted_flag % N
    request = {
        'command': 'decrypt',
        'ciphertext': hex(c)[2:]
    }
    json_send(request)
    response = json_recv()
    s_m_dec = int(response['res'], 16)

    return (s_m_dec * number.inverse(s, N) % N).to_bytes(256, 'big').decode()



if __name__ == "__main__":

    print(solve())
    