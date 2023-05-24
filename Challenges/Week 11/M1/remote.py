import json

from telnetlib import Telnet
from typing import List

from eccrypto import ECDSA
from eccrypto import EllipticCurvePoint

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


def get_challenge(tn: Telnet):
    obj = {"command": "get_challenge"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def reply_challenge(tn: Telnet, solution: List[bool]):
    obj = {"command": "backdoor", "solution": solution}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)

    # TODO ...
    # 1. Get the challenge
    challenge = get_challenge(tn)
    # print(challenge)
    public_point = challenge["public_point"]
    print(public_point)
    challenges = challenge["challenge"]
    ECDSAinstance = ECDSA()


    # 2. Solve the challenge
    bools = []
    for c in challenges:
        bools.append(ECDSAinstance.verify(c["msg"].encode(), bytes.fromhex(c["r"]), bytes.fromhex(c["s"]), bytes.fromhex(public_point)))

    print(bools)

    # 3. Reply the challenge
    res = reply_challenge(tn, bools)
    print(res)




if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51101
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
