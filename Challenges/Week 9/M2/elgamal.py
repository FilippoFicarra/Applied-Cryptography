import secrets
from typing import Tuple
from Crypto.Util import number
from Crypto.PublicKey import ElGamal

import telnetlib
import json
import random
from Crypto.Random import get_random_bytes

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50902)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

class ElGamalImpl:

    @classmethod
    def decrypt(cls, key: ElGamal.ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """
        p = int(key.p)
        g = int(key.g)
        x = int(key.x)

        c1 = int.from_bytes(c1, 'big')
        c2 = int.from_bytes(c2, 'big')

        K = pow(c1, x, p)
        Z = number.inverse(K, p)

        m = (c2 * Z) % p

        return m.to_bytes((m.bit_length()+7)//8, 'big')

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """

        y_b = int(key.y)
        p = int(key.p)
        g = int(key.g)
        q = int((p-1)//2)


        k = p-1

        K = pow(y_b, k, p)

        c1 = pow(g, k, p)
        c2 = (K * int.from_bytes(msg, 'big'))%p

        return c1.to_bytes((c1.bit_length()+7)//8, 'big') , c2.to_bytes((c2.bit_length()+7)//8, 'big')
    
if __name__ == "__main__":

    # key with which I have to encrypt
    request = {
        'command': 'get_public_parameters', 
    }
    json_send(request)

    response = json_recv()
    print(response)

    p_enc = int(response['p'])
    g_enc = int(response['g'])

    # key with which I decrypt
    key_dec = ElGamal.generate(512, get_random_bytes)

    request = {
        'command': 'set_response_key',
        'p': int(key_dec.p),
        'g': int(key_dec.g),
        'y': int(key_dec.y),
    }

    json_send(request)
    response = json_recv()

    print(response)


    e = ElGamalImpl()
        

    key = ElGamal.construct(
                (p_enc, g_enc, g_enc)
    )
    
    msg = b'backdoor'

    c1, c2 = e.encrypt(key, msg)

    request = {
            'command': 'encrypted_command', 
            'encrypted_command': {
                'c1': c1.hex(),
                'c2': c2.hex()
            }
        }
    json_send(request)
    response = json_recv()

    c1_enc = bytes.fromhex(response["encrypted_res"]['c1'])
    c2_enc = bytes.fromhex(response["encrypted_res"]['c2'])


    
    
    e = ElGamalImpl()
    m = e.decrypt(key_dec, c1_enc, c2_enc)

    print(m)
