import multiprocessing
import telnetlib
import json
from string import ascii_lowercase
import itertools
from Crypto.Hash import SHA256, HMAC

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50504)


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

def find_password(salt, chunk):
    pw = {}
    for s in chunk:
        s = ''.join(s)
        pw[HMAC.new(bytes.fromhex(salt), msg=s.encode(), digestmod=SHA256).hexdigest()] = s
    return pw

def solve():
    request = {
            'command' : 'salt',
        }
    json_send(request)

    response = json_recv()
    
    salt = response["salt"]
    combinations = itertools.product(ascii_lowercase, repeat=5)

    c = [item for item in combinations]
    chunk_size = 100000
    chunks = [list(c[i:i+chunk_size]) for i in range(0, len(c), chunk_size)]


    with multiprocessing.Pool() as pool:
        results = [pool.apply_async(find_password, args=(salt, chunk)) for chunk in chunks]
        pw = {}
        for r in results:
            pw.update(r.get())
        
    for i in range(5):
        request = {
            'command' : 'password',
        }
        json_send(request)

        response = json_recv()
        
        password = response["pw_hash"]

        

        request = {
            'command' : 'guess',
            'password' : pw[password]
        }
        json_send(request)

        response = json_recv()

    request = {
        'command' : 'flag',
    }
    json_send(request)

    response = json_recv()
    return response["flag"]

if __name__ == "__main__":

    flag = solve()
    print(flag)
    



