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
    In orther to do so I exploited the fact that the server has a certain syntax for storing the token, that
    when decrypted it will be parsed as desired.
    The principal part was:
        - we should be able to inject the role=admin field in the username so that it is before 
            the one added by the server
    With this two conditions, we can be sure that role=admin is parsed berfore role=user and then we are registered as admin.
    After we are registered as admins we can login and change the settings, and get our coffee!
    """
    request = {
        'command' : 'register',
        'username' : 'Filippo&role=admin', # here we inject the role=admin field
        'favourite_coffee' : 'Cappuccino'
    }
    json_send(request)

    response = json_recv()

    token = response["token"]
    
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
    



