import telnetlib
import json

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50403)

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

"""
    ptxt = (
        b"filename="
        + file_name
        + b"&data="
        + data
        + b"&secret_byte="
        + self.secret_byte
    )
    this is the plaintext that will be encrypted(decrypted) by the server
"""

def find_dk(m : str):
    """
    Here the use of the block of 00 is not to have influence when xoring with the decryption
    of the subsequent block, so that we can easily get the decryption to use later.
    """
    request = {
        'command' : 'encrypt',
        'file_name' : 'flg.txt', # this is one block
        "data" : "00"*10 + "00"*16 + m # this is 1 block (data00...00) +  1 block of 0's + 1 block of m
    }
    json_send(request)

    response = json_recv()


    blocks = blockify(bytes.fromhex(response["ctxt"]))

    return blocks[3]

def solve():

    for _ in range(10):

        D_K_pad = find_dk((int.to_bytes(16, 1, "big")*16).hex()) # we first find the decryption of a full padded block

        request = {
            'command' : 'encrypt',
            'file_name' : 'flg',
            "data" : ''
        } # this will return the encrytion(decryption) of 1 block(filename..+ data) and the encryption of the secret byte
        json_send(request)

        response = json_recv()

        blocks_2 = blockify(bytes.fromhex(response["ctxt"]))

        c_2 = blocks_2[2] # this is the block corresponding to the xor of secret byte and decryption of full padded block

        p_1 = byte_xor(c_2, D_K_pad) # xoring back again we get the scecret byte block (in this case is "a=&secret_byte=?", where ? is the unknown byte)

        guess = p_1[-1].to_bytes(1, "big").hex() # this take the last byte

        request = {
            'command' : 'solve',
            'solve' : guess,
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
    



