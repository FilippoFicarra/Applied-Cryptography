def PKCS_7(s : str, k : int):
    b = s.encode("utf-8")
    l = len(b)
    b=b.hex()
    if ((k-l)%k) == 0 :
        ll = k
    else:
        ll = (k-l)%k
    for i in range(ll):
        b += int.to_bytes(ll, 1, "big").hex()
    return b 

print(PKCS_7("flag", 16))

from collections import Counter


def AES2():
    d = {}
    with open('Challenges/Week 2/aes.data') as f:
        lines = f.readlines()
    for line in lines:
        # l = [line[i:i+32] for i in range(0, len(line), 32)]
        most_frequent_block = dict(Counter([line[i:i+32] for i in range(0, len(line), 32)]))
        most_frequent_block = {k: v for k, v in sorted(most_frequent_block.items(), key=lambda item: item[1], reverse=True)}
        d[line] =  list(most_frequent_block.values())[0]
        print("-"*100)
    print(list({k: v for k, v in sorted(d.items(), key=lambda item: item[1], reverse=True)})[0])
        
        
AES2()

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
def M3():
    iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")
    enc = "79b04593c08cb44da3ed9393e3cbb094ad1ea5b7af8a40457ce87f2c3095e29980a28da9b2180061e56f61cd3ee023ebb08e8607bc44ae37682b1a4a39ca7eaf285b32f575a8bfb630ccd1548c6a7c6d78ceec8e1f45866a0f17bf5216c29ca3"

    key_length = 16

    for i in range(65535):
        seed = i.to_bytes(2, byteorder='big')
        hash_object = SHA256.new(seed)
        aes_key = hash_object.digest()
        trunc_key = aes_key[:key_length]
        cipher = AES.new(trunc_key, AES.MODE_CBC, iv)
        try:
            plaintext = cipher.decrypt(bytes.fromhex(enc)).decode("utf-8")
            print(plaintext)
        except:
            pass
         
M3()