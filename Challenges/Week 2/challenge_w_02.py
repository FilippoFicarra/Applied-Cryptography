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


def AES():
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
        
        
AES()