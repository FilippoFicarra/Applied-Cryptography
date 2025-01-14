import telnetlib
import json
from Crypto.Util.Padding import pad, unpad

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50402)

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

def block_crack(full_message_blocks, flag_m0, last_block):
    found  = b''
    a = full_message_blocks[0]

    for j in range(1,17):
        found = byte_xor(byte_xor(found, (j-1).to_bytes(1, "big")*(j-1)),j.to_bytes(1,"big")*(j-1)) if j > 1 else b'' # at the beginning is empty, then it is the the bytes found that gives
                                                                                                                      # the correct padding, translated so that they give the correct bytes 
                                                                                                                      # for the current padding that we clain
        b = full_message_blocks[0][:16-j] if 16-j > 0 else b''
        for i in range(256): # we look for the bytes that gives the padding desired
            
            full_message_blocks[0] = (b + i.to_bytes(1, "big") + found)
            
            request = {
                'command' : 'decrypt', 
                'm0' : flag_m0,
                'c0' : full_message_blocks[0].hex(),
                'ctxt' : full_message_blocks[1].hex()
               
            }
            json_send(request)

            response = json_recv()
            try:
                res = response["res"] # if this the case we have correct padding
                try :
                    if j == 1 and last_block: # for the last block and first byte we could have a false positive, i.e. we are recovering the real padding instead of \x01
                        l = len(b)-1 if len(b) > 1 else 0
                        c = (i-1).to_bytes(1,"big") if len(b) > 0 else b''
                        request = {
                            'command' : 'decrypt', 
                            'm0' : flag_m0,
                            'c0' : (b[:l] + c + i.to_bytes(1, "big") + found)[:16].hex(),
                            'ctxt' : full_message_blocks[1].hex()
                        
                        }
                        json_send(request)

                        response = json_recv()
                        
                        res = response["res"]
                    found = full_message_blocks[0][-j:] # we save the bytes that gives the correct padding
                    break
                except:
                    pass
            except:
                pass

    # we recover the entire message xoring the full block that gives \x10....\x10 padding, with \x10....\x10 and then back with the original ciphertext to get the plaintext block
    message = byte_xor(byte_xor(full_message_blocks[0], int.to_bytes(16,1,"big")*16),a) 
    full_message_blocks[0] = a
    return message


def solve():

    request = {
        'command' : 'flag',
    }
    json_send(request)

    response = json_recv()
    

    flag_m0 = response["m0"]
    flag_c0 = response["c0"]
    flag_ctxt = response["ctxt"]


    blocks = [bytes.fromhex(flag_c0)]+[bytes.fromhex(flag_ctxt[i:i+32]) for i in range(0,len(flag_ctxt),32)]
    
    message = []
    c0 = flag_c0
    m0 = flag_m0

    # this is pratically a padding oracle attack starting from the first block, due to the fact that we need m0
    for i in range(len(blocks)-1):
        crack = block_crack(blocks[i:i+2], m0, i == len(blocks)-2)
        message.append(crack)
        m0 = crack.hex() # we update m0 with the message retrieved

    return unpad(b"".join(message),16).decode()
        


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



