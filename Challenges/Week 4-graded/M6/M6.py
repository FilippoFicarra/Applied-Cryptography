import telnetlib
import json


def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]

server = "localhost"#"aclabs.ethz.ch"
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


def solve():
    
    request = {
        'command' : 'init',
    }
    json_send(request)

    response = json_recv()

    m0 = response["m0"]
    c0 = response["c0"]
    ctxt = response["ctxt"]

    print(f"m0: {m0}\nc0: {c0}\nctxt: {ctxt}")

    request = {
        'command' : 'metadata_leak',
        'm0' : m0,
        'c0' : c0,
        'ctxt' : ctxt[:32] + ctxt[64:] 
    }
    json_send(request)
    response = json_recv()

    print(response)

    try:
        metadata = response['metadata'].split(' ')

        sender = metadata[5]

        receiver = metadata[7]
        receiver = receiver[:len(receiver)-1]

        time_stamp = metadata[-1]
        time_stamp = time_stamp[:len(time_stamp)-1]

        version = metadata[2]

        print(f"Sender {sender}, receiver {receiver}, time_stamp {time_stamp}, version {version}")
    except:
        print(response)




    

  


if __name__ == "__main__":
    flag = solve()
    # print(flag)
    



