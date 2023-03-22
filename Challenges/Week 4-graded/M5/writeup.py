from datetime import datetime
import re
import telnetlib
import json
from string import ascii_letters, digits
import time

ALPHABET = ascii_letters + digits

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50405)

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


def solve():
    
    request = {
        'command' : 'init',
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
    metadata = src+rcv+ts+majv+minv+int.to_bytes(2, 1, "little") 

    # I xor the the third block of ciphertext with the metadata, so that I find the enc of ciphertext 2 and the additional metadata,
    # and then we xor with proto_header (so that when decrypting proto_header will be deleted)
    proto_xor_c2_xor_additional_enc = byte_xor(byte_xor(bytes.fromhex(ctxt[64:96]), metadata), proto_header) 
                                                                                                                
    
    # I send the max number of blocks (max number that can be encoded with 1 byte(255))
    request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : (bytes.fromhex(ctxt[:32])+proto_xor_c2_xor_additional_enc+int.to_bytes(0,1,"little")*255*16).hex()
    }
    json_send(request)
    response = json_recv()


    src, rcv, ts, majv, minv = parse_repr(response['metadata'])

    # this will be the the ciphertext 2 xor cipertext 1 xor additional_metadata
    new_block_incomplete = src+rcv+ts+majv+minv

    # I retrieve the additional_metadata but the last characters
    incomplete_additional_metadata = byte_xor(byte_xor(new_block_incomplete, bytes.fromhex(ctxt[32:62])), bytes.fromhex(ctxt[:30])) 

    # I then create a dictionary that maps each number to a char, the number is the xor of the last char of the ciphertext 2 and the last char of the ciphertext 1, 
    # everything xored with the char 
    lengths = {}
    for char in ALPHABET:
        lengths[int.from_bytes(byte_xor(byte_xor(char.encode(), bytes.fromhex(ctxt[62:64])), bytes.fromhex(ctxt[30:32])), "little")] = char
    nums = sorted(lengths.keys(), reverse=True)


    i=0
    # I look for the greater number of len such that we have no error, that will correspond to the missing character
    for i in nums:
        request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : (bytes.fromhex(ctxt[:32])+proto_xor_c2_xor_additional_enc+int.to_bytes(0,1,"little")*(i-1)*16).hex()
        }
        json_send(request)
        response = json_recv()
        try:
            response["error"]
            break
        except:
            pass

    request = {
        'command' : 'flag',
        'solve' : incomplete_additional_metadata[:15].decode()+lengths[i]
    }
    json_send(request)
    response = json_recv()

    return response["flag"]


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



