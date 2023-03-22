import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50401)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def solve():
    """
    The fundamental request is the register one. We aim to register a user as an admin.
    In orther to do so I exploited the fact that the server has a certain syntax for storing the token so that,
    when decryptying it will be parsed as desired.
    The principal part were:
        - all the different fields should be a block long
        - we should be able to inject the role=admin field in the username so that it is before 
            the one added by the server
    With this two conditions, we can be sure that role=admin is parsed berfore role=user and then we are registered as admin.
    """
    request = {
        'command' : 'register',
        'username' : '0000000username=000000000000&role=admin',
        'favourite_coffee' : 'Cappuccino000000'
    }
    json_send(request)

    response = json_recv()

    token = response["token"][32:]
    
    request = {
        'command' : 'login',
        'token' : token,
    }
    json_send(request)

    response = json_recv()

    request = {
        'command' : 'change_settings',
        'good_coffee' : "true"
    }
    json_send(request)

    response = json_recv()

    request = {
        'command' : 'get_coffee',
    }
    json_send(request)

    response = json_recv()

    return response["res"]

if __name__ == "__main__":
    flag = solve()
    print(flag)
    



