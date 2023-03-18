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



def solve():

    for i in range(10):
        request = {
            'command' : 'encrypt',
            'file_name' : 'flg.txt',
            "data" : "00"*10 + "00"*16 + (int.to_bytes(16, 1, "big")*16).hex()
        }
        json_send(request)

        response = json_recv()

        blocks = blockify(bytes.fromhex(response["ctxt"]))

        D_K_pad = blocks[3]

        request = {
            'command' : 'encrypt',
            'file_name' : 'flg',
            "data" : ''
        }
        json_send(request)

        response = json_recv()

        blocks_2 = blockify(bytes.fromhex(response["ctxt"]))

        c_2 = blocks_2[2]

        p_1 = byte_xor(c_2, D_K_pad)

        guess = p_1[-1].to_bytes(1, "big").hex()

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
    



