import telnetlib
import json


server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51001)


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
    p = 2**127 - 1
    TAG_LEN = 16

    request = {
        "command": "encrypt",
        "message": "Give me a flat!",
        "nonce": (b'\x00' * 8).hex()
    }
    json_send(request)
    response = json_recv()

    c_1 = bytes.fromhex(response["ciphertext"])
    t_1 = bytes.fromhex(response["tag"])

    # note: the nonce is fixed, so the mask is fixed
    request = {
        "command": "encrypt",
        "message": "Give me a fleg!",
        "nonce": (b'\x00' * 8).hex()
    }
    json_send(request)
    response = json_recv()

    c_2 = bytes.fromhex(response["ciphertext"])
    t_2 = bytes.fromhex(response["tag"])

    t_1_int = int.from_bytes(t_1, "big")
    t_2_int = int.from_bytes(t_2, "big")
    c_1_int = int.from_bytes(c_1, "big")
    c_2_int = int.from_bytes(c_2, "big")

    # k_squared is given because mask is fixed for a fixed nonce
    # t_1_int = (h_1 + mask_int) % p
    # h_1 = (k**3  + c_1_int * k**2 + 15 * k) % p
    # t_1_int = (k**3  + c_1_int * k**2 + 15 * k + mask_int) % p
    # t_2_int = (k**3  + c_2_int * k**2 + 15 * k + mask_int) % p

    # we subtract the two equations to get
    k_squared = ((t_1_int - t_2_int)  * pow(c_1_int-c_2_int, -1, p)) % p
    
    # mask_int = (t_1_int - h_1) % p
    # we can use ctr mode to forge a ciphertext, since we know the plaintext and we know that the cipher block outputs the same value (we choose the same nonce)
    c_forge = byte_xor(byte_xor(c_1, b"Give me a flat!"),b'Give me a flag!')
    c_forge_int = int.from_bytes(c_forge, "big")

    # h_forge = (k**3  + int.from_bytes(c_forge, "big") * k**2 + 15 * k) % p
    # t_forge = (h_forge + mask_int) % p
    # t_forge = (h_forge + (t_1_int - h_1)) % p
    # t_forge = ((k**3  + c_forge_int * k**2 + 15 * k) % p + t_1_int - ((k**3  + c_1_int * k**2 + 15 * k) % p)) % p
    t_forge = (t_1_int + (c_forge_int-c_1_int)* k_squared) % p

    request = {
        "command": "decrypt",
        "ciphertext": c_forge.hex(),
        "tag": t_forge.to_bytes(TAG_LEN, "big").hex(),
        "nonce": (b'\x00' * 8).hex()
    }
    json_send(request)
    response = json_recv()

    flag = response["res"]
    return flag


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



