import telnetlib
import json
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51201)

RSA_KEYLEN = 1024
RAND_LEN = 256
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8
CURVE_NAME = "secp256r1"

CURVE_P_LEN = 32

def point_to_bytes(point: ECC.EccPoint):
    y = int(point.y).to_bytes(CURVE_P_LEN, "big")
    x = int(point.x).to_bytes(CURVE_P_LEN, "big")
    return x + y

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
        "command": "get_public_key",
    }
    json_send(request)
    response = json_recv()
    x = response["x"]
    y = response["y"]

    print(response)

    request = { 
        "command": "client_hello",
        "eph_x" : x,
        "eph_y" : y, 
        "id" : "admin"
    }
    json_send(request)
    response = json_recv()
    eph_x = response["eph_x"]
    eph_y = response["eph_y"]
    signature = bytes.fromhex(response["signature"])
    print(response)

    request = { 
        "command": "client_hello",
        "eph_x" : eph_x,
        "eph_y" : eph_y, 
        "id" : "server", 
        "signature" : signature.hex()
    }
    json_send(request)
    response = json_recv()
    print(response)


    # client_eph = ECC.EccPoint(x, y, curve=CURVE_NAME)
    # server_eph = ECC.EccPoint(eph_x, eph_y, curve=CURVE_NAME)

    # shared = server_eph.d * client_eph
    # key_raw = point_to_bytes(shared)
    # shared_key = HKDF(
    #     master=key_raw,
    #     salt=None,
    #     key_len=32,
    #     hashmod=SHA256,
    #     context=b"aead encryption",
    # )

    # transcript = point_to_bytes(client_eph) + point_to_bytes(server_eph.pointQ)
    # h = SHA256.new(transcript)

if __name__ == "__main__":
    solve()
    



