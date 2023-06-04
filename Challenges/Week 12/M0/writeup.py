import telnetlib
import json
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51200)

RSA_KEYLEN = 1024
RAND_LEN = 256
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"{len(a)}, {len(b)}"
    return bytes(x ^ y for x, y in zip(a, b))


def solve():
    p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
    q = (p - 1) // 2
    g = 3


    request = {
        "command": "client_hello",
    }
    json_send(request)
    response = json_recv()
    client_nonce = bytes.fromhex(response["client_nonce"])
    # print(response)

    request = {
        "command": "boss_hello",
        "client_nonce": response["client_nonce"],
    }
    json_send(request)
    response = json_recv()
    pub_key = int(response["pubkey"])
    boss_nonce = bytes.fromhex(response["boss_nonce"])
    # print(response)

    request = {
        "command": "client_finished",
        "pubkey": pub_key,
        "boss_nonce": response["boss_nonce"],
    }
    json_send(request)
    response = json_recv()
    # print(response)
    encrypte_shared_key_c1 = response["encrypted_shared_key"]["c1"]
    encrypte_shared_key_c2 = response["encrypted_shared_key"]["c2"]
    ciphertext = bytes.fromhex(response["ciphertext"])
    nonce = bytes.fromhex(response["nonce"])

    request = {
        "command": "boss_finished",
        "encrypted_shared_key": response["encrypted_shared_key"],
        "ciphertext": response["ciphertext"],
        "nonce": response["nonce"],
    }
    json_send(request)
    response = json_recv()

    request = {
        "command": "compromise",
    }
    json_send(request)
    response = json_recv()
    print(response)
    boss_private = response["secret"]

    K = pow(encrypte_shared_key_c1, boss_private, p)
    shared_secret = (encrypte_shared_key_c2 * pow(K, -1, p)) % p

    secure_key = HKDF(
                master=long_to_bytes(shared_secret),
                key_len=32,
                salt=client_nonce + boss_nonce,
                hashmod=SHA512,
                num_keys=1,
    )
    cipher = AES.new(secure_key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)
if __name__ == "__main__":
    solve()
    



