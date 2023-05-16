import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51003)

RSA_KEYLEN = 1024


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
            # we multiply c by (2**counter)**e, so m is shifted by 2**counter
            c = (int.from_bytes(challenge, "big") * pow(2**counter, e, N)) % N
            request = {
                "command": "decrypt",
                "ctxt": c.to_bytes(RSA_KEYLEN//8, "big").hex()
            }
            json_send(request)
            response = json_recv()
            try:
                if "Error: Decryption failed" in response["error"] : # if we get error the first byte is not 0 and we know how many shift we needed from the message to overflow
                    break
            except:
                continue

        i = RSA_KEYLEN - 8 - (counter - 1) # so the message can be represented by total_bit_len - 8 - (counter - 1) bits, since we shifted by 2**counter


        request = {
            "command": "solve",
            "i": i
        }
        json_send(request)
        response = json_recv()
        
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
    



