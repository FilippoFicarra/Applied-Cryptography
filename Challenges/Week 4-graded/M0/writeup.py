import telnetlib
import json
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50400)

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
    for i in range(64):

        request = {
        'command' : 'query',
        'm' : int.to_bytes(0,16, "big").hex()
        }
        json_send(request)

        response = json_recv()
        ciphertext = response["res"]

        dic_enc = {}
        dic_dec = {}
        """
        The solution is to exploit the fact that, with 2 bytes can have 2^16 different keys. In the server there is a double 
        encryption, if we are in the real world, each with a key of 2 bytes. My approach was to send a know plaintext(0^16), and asking for the 
        encryption. After that I looped trhough all the possible different keys and saving all the encryptions of the plaintext with the key
        and the decryption of the ciphertext with the same key. If at the end there are 2 keys that lead to enc(k1, ptx) = dec(k2, ctxt),
        we are in the real world, otherwise we are in the random world.
        """
        for k in range(2**16):
            key = SHA256.new(k.to_bytes(2,"big")).digest()
            cipher = AES.new(key, AES.MODE_ECB)
            dic_enc[k] = cipher.encrypt(int.to_bytes(0,16, "big"))
            dic_dec[k] = cipher.decrypt(bytes.fromhex(ciphertext))
        
        s = set(dic_enc.values()).intersection(set(dic_dec.values()))
     
        b = 0 if len(s) != 0 else 1
        request = {
            'command' : 'guess',
            'b' : b
        }

        json_send(request)

        response = json_recv()

    request = {
        'command' : 'flag',
    }

    json_send(request)

    response = json_recv()

    return response["flag"]


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



