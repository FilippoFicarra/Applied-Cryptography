from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50800)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)
    """
    e = 65537
    while True:
        p = number.getPrime(nbits // 2)
        q = number.getPrime(nbits // 2)
        if p != q and math.gcd(e, (p - 1)) == 1 and math.gcd(e, (q - 1)) == 1 and number.size(p*q) == nbits:
            break
    
    N = p * q
    d = number.inverse(e, (p - 1) * (q - 1))

    return (N, e), (N, d), (p, q)


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """
    N, e = pk
    return pow(m, e, N)


def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """
    N, d = sk
    return pow(c, d, N)

if __name__ == "__main__":
    pk, sk, primes = rsa_key_gen()

    N, e = pk
    N, d = sk
    p, q = primes

    request = {
        'command': 'set_parameters', 
        'N' : N,
        'e' : e,
        'd' : d,
        'p' : p,
        'q' : q
    }
    json_send(request)

    response = json_recv()
    print(response)
    request = {
        'command': 'encrypted_flag', 
    }
    json_send(request)

    response = json_recv()
    enc_message = response['res'].split(':')[1].lstrip()

    # print(enc_message)

    flag = rsa_dec(sk, int(enc_message)).to_bytes(256, 'big').decode()
    print(flag)


