import math
import telnetlib
import json

server = "localhost"#"aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51004)
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

def ceil(a: int, b: int) -> int:
    # Necessary because of floating point precision loss
    return a // b + (1 if a % b != 0 else 0)

def get_multiplier(m_max: int, m_min: int, N: int, B: int) -> int: 
    tmp = ceil(2 * B, m_max - m_min)
    r=tmp * m_min//N
    alpha = ceil(r * N, m_min)
    return alpha


def solve():

    request = {
        "command": "flag",
    }
    json_send(request)
    response = json_recv()
    enc_flag = bytes.fromhex(response["flag"])


    request = {
        "command": "get_params",
    }
    json_send(request)
    response = json_recv()
    N = int(response["N"])
    e = int(response["e"])

    # step 1
    counter = 0
    while True:
        counter += 1
        c = (int.from_bytes(enc_flag, "big") * pow(2**counter, e, N)) % N
        request = {
            "command": "decrypt",
            "ctxt": c.to_bytes(N.bit_length()//8, "big").hex()
        }
        json_send(request)
        response = json_recv()
        try:
            if "Error: Decryption failed" in response["error"] :
                break
        except:
            continue

    i = N.bit_length() - 8 - (counter - 1)


    m_max = 2**i
    m_min = 2**(i-1)
    B = 2**(N.bit_length()-8)


    # step 2
    # find α0 such that α0 · m incurs a modular reduction, but (α0 − 1)m does not.
    # modular reduction happen if the error message is not the one of m[0] != 0

    alpha_0 = 2**(counter) # we already know that the error "Error: Decryption failed" appears from here on, until we have a modular reduction
    while True:
        c = (int.from_bytes(enc_flag, "big") * pow(alpha_0, e, N)) % N
        request = {
            "command": "decrypt",
            "ctxt": c.to_bytes(N.bit_length()//8, "big").hex()
        }
        json_send(request)
        response = json_recv()
        # print(response)
        alpha_0 += 1 # otherwise m_min_1 is not the smallest and it is a contradiction
        try:
            if "Eror: Decryption failed" in response["error"] :
                alpha_0 -= 1
                break
        except:
            continue

    # print("alpha_0 = ", alpha_0)
    # print("N = ", N)
    m_min = ceil(N, alpha_0)
    m_max = ceil(N , (alpha_0 - 1)) #this is wrong for sure, but I don't know how to find the correct one by now

    # step 3
    while m_min != m_max - 1:


        alpha = get_multiplier(m_max, m_min, N, B)

        print("ɑ =", alpha)

        break







    
    flag = ""

    return flag


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



