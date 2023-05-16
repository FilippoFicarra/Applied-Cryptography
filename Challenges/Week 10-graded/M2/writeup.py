import telnetlib
import json
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util import number

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51002)


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

def find_exponent(g, h, p, q):
    """
    Find the exponent x such that g^x = h (mod p).
    """
    for x in range(q):
        if pow(g, x, p) == h:
            return x
    return None



def solve():
    # I fix an upperbound for the order of the subgroup
    q = 1001
    while True:
        if q < 1000: 
            if (p-1)%q == 0:
                g = pow(h, (p-1)//q, p) #find a g such that we have small subgroup and we can bruteforce to solve the discrete log
                if g != 1 and g != 0 and g != p-1: #check if g is not trivial
                    break
            q = q + 1
        else: # if we can not find out a small subgroup, we generate a new prime number
            q = 2
            p = number.getPrime(1024)
            h = number.getRandomRange(1, p-1)

    request = {
        "command": "set_params",
        "p": p,
        "g": g
    }
    json_send(request)
    response = json_recv()

    bob_pubkey = response["bob_pubkey"]


    request = {
        "command": "encrypt",
    }
    json_send(request)
    response = json_recv()

    pk = response["pk"]
    ciphertext = response["ciphertext"]
    tag = response["tag"]
    nonce = response["nonce"]
    
    # since q is small we can bruteforce to find the exponent
    sk = find_exponent(g, pk, p, q)

    # we just need to compute the shared key
    shared = pow(bob_pubkey, sk, p)
    shared_bytes = shared.to_bytes(512, "big")
    pk_bytes = pk.to_bytes(512, "big")
    bob_pubkey_bytes = bob_pubkey.to_bytes(512, "big")

    K: bytes = HKDF(shared_bytes + pk_bytes + bob_pubkey_bytes, 32, salt=b"", num_keys=1, context=b"dhies-enc", hashmod=SHA256) #type: ignore
    cipher = AES.new(K, AES.MODE_GCM, nonce=bytes.fromhex(nonce))
    flag = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))

    return flag.decode()


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



