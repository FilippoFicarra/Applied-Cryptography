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
    request = {
        'command' : 'encrypt',
        'file_name' : 'flg.txt',
        "data" : "00"*10 + "00"*16 + m
    }
    json_send(request)

    response = json_recv()


    blocks = blockify(bytes.fromhex(response["ctxt"]))

    return blocks[3]

def solve():
    
    D_K_full_pad = find_dk((int.to_bytes(16, 1, "big")*16).hex())
    
    encrypted_flag_response = []
    for i in range(16):
        request = {
            'command' : 'encrypt',
            'file_name' : 'flg.txt',
            "data" : "00"*10 + "00"*i
        }
        json_send(request)

        response = json_recv()
        resp_blocks = blockify(bytes.fromhex(response["ctxt"]))
        try:
            encrypted_flag_response.append(byte_xor(resp_blocks[-1], D_K_full_pad).decode())
            break
        except:
            pass

    print(encrypted_flag_response)


    for i in range(2, len(resp_blocks)-2): # type: ignore
        D_K = find_dk(encrypted_flag_response[i-2].encode().hex())
        
        encrypted_flag_response.append(byte_xor(resp_blocks[-i], D_K).decode()) # type: ignore

    decryption = "".join(encrypted_flag_response[::-1]).split("=")[1]
    return decryption

    

  


if __name__ == "__main__":
    flag = solve()
    print(flag)
    



