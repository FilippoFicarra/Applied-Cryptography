import telnetlib
import json

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50404)

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

def find_enc():

    D_K_full_pad = find_dk((int.to_bytes(16, 1, "big")*16).hex())

    encrypted_flag_response = []
    resp_blocks = []

    for i in range(16):
        request = {
            'command' : 'encrypt',
            'file_name' : 'flg.txt',
            "data" : "00"*10 + "00"*i
        }
        json_send(request) # This request is useful to find the full message length such that the padding is a full block

        response = json_recv()
        resp_blocks = blockify(bytes.fromhex(response["ctxt"]))
        try:
            encrypted_flag_response.append(byte_xor(resp_blocks[-1], D_K_full_pad).decode()) # with this i can check if the xor of the last block decryption with the previous ciphertext is a valid ascii, i.e. it is part of the flag
            break
        except:
            pass

    return resp_blocks, encrypted_flag_response # I return the full message encrypted divided by blocks and thearray containing the first block of the flag

def solve():
    
    
    resp_blocks, encrypted_flag_response = find_enc()
    """
    I iterate in order to to the same procedure as before , i.e. find the decryption of the block and xoring with the previous ciphertext
    """
    for i in range(2, len(resp_blocks)-2): # I start from 2 because we already found the last block of the flag.
        # this finds the decryption of bloc i-2
        D_K = find_dk(encrypted_flag_response[i-2].encode().hex()) 
        
        encrypted_flag_response.append(byte_xor(resp_blocks[-i], D_K).decode())

    # I just revers the order of the array since we went backward in retrieving, and split to get the flag field
    decryption = "".join(encrypted_flag_response[::-1])
    return decryption


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



