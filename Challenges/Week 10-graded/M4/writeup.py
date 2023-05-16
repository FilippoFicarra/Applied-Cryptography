import telnetlib
import json
from Crypto.Hash import SHAKE256

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 51004)

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

def ceil(a: int, b: int) -> int:
    # Necessary because of floating point precision loss
    return a // b + (1 if a % b != 0 else 0)

def get_multiplier(m_max: int, m_min: int, N: int, B: int) -> int: 
    tmp = ceil(2 * B, m_max - m_min)
    r=tmp * m_min//N
    alpha = ceil(r * N, m_min)
    return alpha, r

def find_len(enc_flag: bytes, N: int, e: int):
    counter = 0
    while True:
        counter += 1
        c = (int.from_bytes(enc_flag, "big") * pow(2**counter, e, N)) % N
        request = {
            "command": "decrypt",
            "ctxt": c.to_bytes(RSA_KEYLEN//8, "big").hex()
        }
        json_send(request)
        response = json_recv()
        try:
            if "Error: Decryption failed" in response["error"] :
                break
        except:
            continue

    i = N.bit_length() - 8 - (counter - 1)
    return i, counter

def find_alpha_0(alpha_0: int, N: int, e: int, enc_flag: bytes):
    while True:
        c = (int.from_bytes(enc_flag, "big") * pow(alpha_0, e, N)) % N
        request = {
            "command": "decrypt",
            "ctxt": c.to_bytes(N.bit_length()//8, "big").hex()
        }
        json_send(request)
        response = json_recv()
        alpha_0 += 1
        try:
            if "Eror: Decryption failed" in response["error"] : # we found the first alpha_0 that incurs a modular reduction
                return alpha_0 - 1
        except:
            continue

def decode_msg(m : int):
    m_bytes=m.to_bytes(RSA_KEYLEN // 8, 'big')
    rand = m_bytes[1:1+RAND_LEN//8]
    ptxt_masked = m_bytes[1+RAND_LEN//8:]

    rand_hashed = SHAKE256.new(rand).read(P_LEN)
    ptxt_padded = xor(ptxt_masked, rand_hashed)

    for i, b in enumerate(ptxt_padded):
        if b == 1 and all(ch == 0 for ch in ptxt_padded[:i]):
            try:
                return ptxt_padded[i+1:].decode()
            except:
                return ""
    return ""

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
    i, counter = find_len(enc_flag, N, e)

    m_max = 2**i
    m_min = 2**(i-1)
    B = 2**(RSA_KEYLEN-8)

    # step 2
    # find α0 such that α0 · m incurs a modular reduction, but (α0 − 1)m does not.
    # modular reduction happen if the error message is not the one of m[0] != 0
    alpha_0 = 2**(counter) # we already know that the error "Error: Decryption failed" appears from here on, until we have a modular reduction
    alpha_0 = find_alpha_0(alpha_0, N, e, enc_flag)


    # (alpha_0 - 1) * m < N <= alpha_0 * m
    m_min = ceil(N, alpha_0)
    m_max = ceil(N , (alpha_0 - 1))

    
    alpha, r = get_multiplier(m_max, m_min, N, B)


    # step 3
    # use this if our binary search gets stuck
    prev_m_min = m_min
    prev_m_max = m_max

    while m_min != m_max - 1 :

        # we send c * alpha^e mod N, so alpha*m mod N is the message we want to decrypt
        request = {
            "command": "decrypt",
            "ctxt": ((int.from_bytes(enc_flag, "big") * pow(alpha, e, N)) % N).to_bytes(N.bit_length()//8, "big").hex()
        }
        json_send(request)
        response = dict(json_recv())
        if "error" in response.keys() and "Error: Decryption failed" in response["error"]: # alpha * m mod N overflows the first byte
            m_min = ceil((B + r * N),alpha) # message is in the upper half 
        else:
            m_max = ceil((B + r * N),alpha) # message is in the lower half, because alpha * m mod N does not overflow the first byte
        

        # get new multiplier
        alpha, r = get_multiplier(m_max, m_min, N, B)

        if prev_m_max == m_max and prev_m_min == m_min: # we are stuck
            break
        prev_m_max = m_max
        prev_m_min = m_min


   
    # we have a range of messages, (theoretically m_min is the only one that is correct, but we can't be sure)
    run = 0
    while m_min+run <= m_max:
        print(decode_msg(m_min+run))
        run += 1

   

if __name__ == "__main__":
    solve()
    



