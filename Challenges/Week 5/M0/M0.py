from Crypto.Hash import MD5, SHA1, SHA256, HMAC
from Crypto.Protocol.KDF import scrypt

# Salt is 20 bytes
def onion(pw_hex, salt_hex, secret_hex):
    pw = bytes.fromhex(pw_hex)
    salt = bytes.fromhex(salt_hex)
    secret = bytes.fromhex(secret_hex)

    h1 = MD5.new(pw).digest()
    h2 = HMAC.new(key=salt, msg=h1, digestmod=SHA1).digest()
    h3 = HMAC.new(key=secret, msg=h2, digestmod=SHA256).digest()
    # Use n = 2**10, r = 32, p = 2, key_len = 64
    h4 = scrypt(password=h3, salt=salt, N=2**10, r=32, p=2, key_len=64) # type: ignore
    h5 = HMAC.new(key=salt, msg=h4, digestmod=SHA256).hexdigest() # type: ignore

    return h5


if __name__ == '__main__':
    PW = '6f6e696f6e732061726520736d656c6c79'
    SECRET = '6275742061726520617765736f6d6520f09f988b'
    SALT = '696e2061206e69636520736f6666726974746f21'
    print(onion(PW, SALT, SECRET))
