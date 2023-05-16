import telnetlib
import json
from Crypto.Hash import SHA256

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51000)


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

def DSA_sign(msg: bytes, sign_key: int, g: int, p: int, q: int, k: int, r: int):
    # Compute the signature
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    s = (pow(k, -1, q) * (h + sign_key * r)) % q
    return r, s

def solve():
    
    request = {
        "command": "get_params"
    }
    json_send(request)
    response = json_recv()

    g = response["g"]
    p = response["p"]
    q = response["q"]
    vfy_key = response["vfy_key"]

    # md5 collides
    m_1 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'
    m_2 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'
    
    request = {
        "command": "sign",
        "message": m_1
    }
    json_send(request)
    response = json_recv()
    r_1 = response["r"]
    s_1 = response["s"]

    request = {
        "command": "sign",
        "message": m_2
    }
    json_send(request)
    response = json_recv()
    r_2 = response["r"]
    s_2 = response["s"]

    # since md5(m_1) = md5(m_2) we can compute k, we know that k_1=k_2 and r_1=r_2 are the same for both messages, we know that s = (pow(k, -1, q) * (h + sign_key * r)) % q

    # we can compute h_1 and h_2 with sha256
    h_1 = int.from_bytes(SHA256.new(bytes.fromhex(m_1)).digest(), "big")
    h_2 = int.from_bytes(SHA256.new(bytes.fromhex(m_2)).digest(), "big")

    # s_1 = (pow(k, -1, q) * (h_1 + sign_key * r_1)) % q
    # s_2 = (pow(k, -1, q) * (h_2 + sign_key * r_2)) % q
    # we subtract the two equations
    # s_1 - s_2 = (pow(k, -1, q) * (h_1 + sign_key * r_1)) % q - (pow(k, -1, q) * (h_2 + sign_key * r_2)) % q
    # s_1 - s_2 = (pow(k, -1, q) * (h_1 + sign_key * r_1 - h_2 - sign_key * r_2)) % q
    # s_1 - s_2 = (pow(k, -1, q) * (h_1 - h_2)) % q
    k = (pow(s_1 - s_2, -1, q) * (h_1 - h_2)) % q

    # given k we can compute the signing key
    sign_key = ((s_2  * k - h_2)* pow(r_2, -1, q)) % q

    # we can now sign the message and get the flag
    r_1, s_1 = DSA_sign(b"Give me a flag!", sign_key, g, p, q, k, r_1)

    request = {
        "command": "flag",
        "r": r_1,
        "s": s_1
    }

    json_send(request)
    response = json_recv()

    flag = response["flag"]
    return flag


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



