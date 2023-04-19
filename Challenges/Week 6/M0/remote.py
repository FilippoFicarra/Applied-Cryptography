#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
import subprocess


tn = telnetlib.Telnet("aclabs.ethz.ch", 50600)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")



request = {
    "command": "token",
}
json_send(request)

response = json_recv()
token = response["token"]
command_string = token["command_string"]
mac = token["mac"]


print(command_string, mac)

data = "&command=flag"

# print(mac)
# print(bytes.fromhex(command_string).decode())
# print(data)


hashpump_command = ['hashpump', '-s', mac, '-a',"&command=flag", '-k', '16', '-d', "command=hello&arg=world"]

output = subprocess.check_output(hashpump_command).split(b"\n")
new_mac = output[0].decode()
new_data = output[1]

print(new_mac)
print(new_data)

data = new_data[:23] + b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x018'+ new_data[-13:]

b = bytes(new_data.decode()[23:len(new_data)-13], "utf-8")
b.replace(b'\\\\', b'\\')
print(b)
print(data)


request = {
    "command": "token_command",
    "token": {
        "command_string": data.hex(),
        "mac": new_mac,
    },
}

json_send(request)

response = json_recv()
print(response)

