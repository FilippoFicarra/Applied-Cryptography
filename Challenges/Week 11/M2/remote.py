import json

from telnetlib import Telnet
from typing import List
from Crypto.Hash import SHA256
from eccrypto import ECDSA

REMOTE = True

ECDSAinstance = ECDSA()
ECDSAinstance.keygen()


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def signed_json_send(tn: Telnet, req: dict):
    req_str = json.dumps(req)

    public_point_compressed_bytes = ECDSAinstance.public_point.to_bytes(
        compression=True
    )
    signature = ECDSAinstance.sign(req_str.encode())

    obj = {
        "command": "signed_command",
        "signed_command": req,
        "public_point": public_point_compressed_bytes.hex(),
        "r": signature[0].hex(),
        "s": signature[1].hex(),
    }
    json_send(tn, obj)


# Use the following 3 functions to send commands to the server
def get_status(tn: Telnet):
    obj = {"command": "get_status"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_debug_info(tn: Telnet):
    obj = {"command": "get_debug_info"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_control(tn: Telnet, d: int):
    obj = {"command": "get_control", "d": d}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res

import matplotlib.pyplot as plt

def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)

    # TODO ...
    # while True:
    debug_info = get_debug_info(tn)
    print(debug_info)
    timings = debug_info["timings"]

    # from k we can compute d since s = (pow(k,-1, self.ec.n)*(h+self.d*r))%self.ec.n
    msg_bytes = debug_info["msg"].encode()
    h = int(SHA256.new(msg_bytes).digest().hex(), 16)
    r = int(debug_info["r"], 16)
    s = int(debug_info["s"], 16)

    # we can compute k from the timings
    # we know that r = G*k with double and add
    # so we can compute the timings for double and add

    bits = []
    for timing in timings:
        if timing < 35000:
            bits.append(0)
        else:
            bits.append(1)
    # reverse the bits
    bits = bits[::-1]
    combination = change_zero_bit_combinations(bits)
    print(bits)
    ks = []
    for comb in combination:
        k = int("".join(map(str, comb)), 2)
        ks.append(k)


    # now we can compute d
    for k in ks:
        d = ((s * k - h) * pow(r, -1, ECDSAinstance.ec.n) )% ECDSAinstance.ec.n

        # now we can get the flag
        flag = get_control(tn, d)
        if "flag" in flag["res"]: 
            print(flag)
            break
  

def change_zero_bit_combinations(bits, index=0, combination=[], combinations=[]):
    if index == len(bits):
        combinations.append(combination[:])  # Add the generated combination to the list
        return

    if bits[index] == 0:
        # First branch: Replace the current bit with 0
        combination.append(0)
        change_zero_bit_combinations(bits, index + 1, combination, combinations)
        combination.pop()

        # Second branch: Replace the current bit with 1
        combination.append(1)
        change_zero_bit_combinations(bits, index + 1, combination, combinations)
        combination.pop()
    else:
        # The bit is already 1, keep it unchanged
        combination.append(1)
        change_zero_bit_combinations(bits, index + 1, combination, combinations)
        combination.pop()

    return combinations


if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51102
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
