import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51003)
from Crypto.Hash import MD5, HMAC, SHA256
from Crypto.Util import number


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

    for _ in range(256):
        request = {
            "command": "get_challenge",
        }
        json_send(request)
        response = json_recv()
        challenge = bytes.fromhex(response["challenge"])

        # print(challenge.hex())

        request = {
            "command": "get_params",
        }
        json_send(request)
        response = json_recv()
        N = int(response["N"])
        e = int(response["e"])

        counter = 0
        while True:
            counter += 1
            c = (int.from_bytes(challenge, "big") * pow(2**counter, e, N)) % N
            request = {
                "command": "decrypt",
                "ctxt": c.to_bytes(512, "big").hex()
            }
            json_send(request)
            response = json_recv()
            # print(response)
            try:
                if "Error: Decryption failed" in response["error"] :
                    break
            except:
                continue

        i = N.bit_length()  - 8 - (counter - 1)

        # print(i)

        request = {
            "command": "solve",
            "i": i
        }
        json_send(request)
        response = json_recv()
        # print(response["res"])
        
    request = {
        "command": "flag",
    }
    json_send(request)
    response = json_recv()
    flag = response["flag"]

    return flag


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



