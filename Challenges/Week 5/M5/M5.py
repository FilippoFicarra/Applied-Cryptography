import multiprocessing
import telnetlib
import json
from string import ascii_lowercase
import itertools
from Crypto.Hash import SHA256, HMAC, MD5

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50505)



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
        'command' : 'token',
    }
    json_send(request)

    response = json_recv()
    nonce = response["nonce"]
    token_enc = bytes.fromhex(response["token_enc"])

    m_ = b"1:Pepper and lemon spaghetti with basil and pine nuts&fav_food_recipe:Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 m"

    m_c = bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70")
    m_C = b"1:" + bytes.fromhex("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70")+b"&fav_food_recipe:"


    c_C = byte_xor(byte_xor(m_, token_enc[16:16+len(m_C)]),m_C)
    token = token_enc[:16] + c_C + token_enc[16+len(m_C):]

    request = {
            'command' : 'login',
            'nonce' : nonce,
            'token_enc' : token.hex(),
            'm2' : m_c.hex()
        }
    json_send(request)
    response = json_recv()
    request = {
            'command' : 'flag',
        }
    json_send(request)
    response = json_recv()
    return response["res"]
    
    
   

if __name__ == "__main__":

    flag = solve()
    print(flag)