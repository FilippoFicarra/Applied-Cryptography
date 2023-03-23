from datetime import datetime
import re
import telnetlib
import json
from string import printable
from Crypto.Util.Padding import pad, unpad

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50406)


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

def parse_repr(metadata):
        """Parses a string representation of a Message, returning the metadata fields"""

        majv, minv, src, rcv, ts = re.match(
            r"Montone Protocol \(v(\d+)\.(\d+)\) message from (\d+) to (\d+), sent on (.+)\.",
            metadata,
        ).groups() # type: ignore

        majv = int(majv).to_bytes(2, "little")
        minv = int(minv).to_bytes(1, "little")
        src = int(src).to_bytes(4, "little")
        rcv = int(rcv).to_bytes(4, "little")
        ts = int(datetime.fromisoformat(ts).timestamp()).to_bytes(4, "little")
        return src, rcv, ts, majv, minv

def block_crack(proto_header, m_prev, c_curr, c_prev, c0, m0, c1):
    # I xor the the third block of ciphertext with the previous block of plaintext, so that I find the enc of c_prev and the additional metadata,
    # and then we xor with proto_header (so that when decrypting proto_header will be deleted)
    proto_xor_c_prev_xor_additional_enc = byte_xor(byte_xor(bytes.fromhex(c_curr), m_prev), proto_header) 
                                                                                                                
    
    # I send the max number of blocks (max number that can be encoded with 1 byte(255))
    request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : (bytes.fromhex(c1)+proto_xor_c_prev_xor_additional_enc+int.to_bytes(0,1,"little")*255*16).hex()
    }
    json_send(request)
    response = json_recv()


    src, rcv, ts, majv, minv = parse_repr(response['metadata'])

    # this will be the the c_prev xor cipertext 1 xor additional_metadata
    new_block_incomplete = src+rcv+ts+majv+minv

    # I retrieve the current_message but the last characters xoring back c1
    m_cur = byte_xor(byte_xor(new_block_incomplete, bytes.fromhex(c_prev)), bytes.fromhex(c1))[:15]

    # I then create a dictionary that maps each number to a char, the number is the xor of the last char of the c_prev and the last char of the ciphertext 1, 
    # everything xored with the char 
    lengths = {}
    for char in printable:
        lengths[int.from_bytes(byte_xor(byte_xor(char.encode(), bytes.fromhex(c_prev[-2:])), bytes.fromhex(c1[-2:])), "little")] = char.encode()
    nums = sorted(lengths.keys())


    i = 0
    j = len(printable)
    k = 0
    error = 0
    # I look for the greater number of len such that we have no error, that will correspond to the missing character
    while(i<j): # thanks to the binary search there is some margin in the number of requests
        k = int((i+j)/2)
        request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : (bytes.fromhex(c1)+proto_xor_c_prev_xor_additional_enc+int.to_bytes(0,1,"little")*(nums[k]-1)*16).hex()
        }
        json_send(request)
        response = json_recv()
        try:
            response["error"]
            error = k
            i=k+1
        except:
            j=k
    return m_cur+lengths[nums[error]]
def solve():
    
    request = {
        'command' : 'flag',
    }
    json_send(request)

    response = json_recv()

    m0 = response["m0"]
    c0 = response["c0"]
    ctxt = response["ctxt"]


    request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : ctxt
    }
    json_send(request)
    response = json_recv()

    src, rcv, ts, majv, minv = parse_repr(response['metadata'])

    proto_header = b"MONTONE-PROTOCOL"


    # I reconstruct the metadata, knowing that the length is 2 blocks (1 block for additional metadata, 1 block for the padding)
    metadata = src+rcv+ts+majv+minv+int.to_bytes(3, 1, "little") 


    message = []
    # i loop to reconstruct the entire message
    for i in range(2, int(len(ctxt)/32)):
        m = block_crack(proto_header, metadata, ctxt[i*32:(i+1)*32], ctxt[(i-1)*32:i*32], c0, m0, ctxt[:32])
        try:
            message.append(unpad(m, 16).decode()) # here i try to unpad since the message metadata is padded and then concatenated with the content(in which is the flag)
        except:
            message.append(m.decode())
        metadata = m
    return "".join(message)

        

if __name__ == "__main__":

    flag = solve()
    print(flag)
    



