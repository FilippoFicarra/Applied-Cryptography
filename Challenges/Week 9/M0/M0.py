import secrets
from Crypto.Util import number
from Crypto.Random import random
import math
import telnetlib
import json
import datetime
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES 
from math import ceil, sqrt

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50900)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")



def solve():
   
    p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
    g = 35347793643784512578718068065261632028252678562130034899045619683131463682036436695569758375859127938206775417680940187580286209291486550218618469437205684892134361929336232961347809792699253935296478773945271149688582261042870357673264003202130096731026762451660209208886854748484875573768029653723060009335


    request = {
        'command': 'alice_initialisation', 
    }
    json_send(request)

    response = json_recv()
    alice_pubkey = response['alice_key']

   

    request = {
        'command': 'bob_initialisation', 
        'alice_hello': {
            'resp' : "Hi Bob, I'm Alice. This is my public key",
            'alice_key' : pow(g, p-1, p)
        }
    }
    json_send(request)

    response = json_recv()

    bob_pubkey = response['bob_key']

    


    eve_bob_key = pow(bob_pubkey, p-1, p)



    


    request = {
            'command': 'alice_finished', 
            'bob_hello': {
                'resp' : "Hi Alice, I'm Bob. This is my public key",
                'bob_key' : pow(g, p-1, p)
        }
    }

    json_send(request)
    response = json_recv()

    print(response)
    encryped_flag = response['encrypted_flag']
    nonce = response['nonce']
    
    shared_bytes = eve_bob_key.to_bytes(eve_bob_key.bit_length(), 'big')
    secure_key = HKDF(master = shared_bytes, key_len = 32, salt = b'Secure alice and bob protocol', hashmod = SHA512, num_keys = 1)

    cipher = AES.new(secure_key, AES.MODE_CTR, nonce = bytes.fromhex(nonce))
    flag = cipher.decrypt(bytes.fromhex(encryped_flag)).decode()

    return  flag



if __name__ == "__main__":

    print(solve())
    