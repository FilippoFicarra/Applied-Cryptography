import json

from telnetlib import Telnet
from typing import List

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

def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)

    # TODO ...


if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51102
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
