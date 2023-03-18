import telnetlib
import json
from datetime import datetime, timezone
import time


def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "localhost"#"aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50405)

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
        'command' : 'init',
    }
    json_send(request)

    response = json_recv()

    m0 = response["m0"]
    c0 = response["c0"]
    ctxt = response["ctxt"]

    print(f"m0: {m0}\nc0: {c0}\nctxt: {ctxt}")
    request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : ctxt,
    }
    json_send(request)

    response = json_recv()

    response = response['metadata'].split(' ')

    sender = response[5]

    receiver = response[7]
    receiver = receiver[:len(receiver)-1]

    time = response[-1]
    time = time[:len(time)-1]

    version = response[2]



    print(f"Sender {sender}, receiver {receiver}, time {time}, version {version}")
 


    

  


if __name__ == "__main__":
    flag = solve()
    # print(flag)
    



