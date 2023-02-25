# M 0.0
import hashlib; 
print("Flag 0 :",hashlib.sha224(b"you made it").hexdigest())

# M 0.1
from Crypto.Hash import SHA256
print("Flag 1 :",SHA256.new(data=b'hi').hexdigest())

# M 0.2 

phrase = b'LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteurs.'
info = b"".join([phrase[i:i+16][len(phrase[i:i+16])-1].to_bytes(1, "big") for i in range(0, len(phrase), 16)])

print("Flag 2 :", SHA256.new(data=info).hexdigest())

# M 0.3

byte = "596f752063616e206465636f646521"

print("Flag 3 :", bytes.fromhex(byte).decode("utf-8"))

# M 0.4

sentence = "ጷ뼯쯾"

print("Flag 4 :", sentence.encode("utf-8").hex())

# M 0.5

byte =  bytes.fromhex("210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002")

for i in range(0, 128):
    a=[]
    for b in byte:
        a.append((b ^ i).to_bytes(1,"big"))
    a = b''.join(a)
    print(a.decode("utf-8"))
    print(i)
    print("-"*50)

# M 0.6

plaintext = "Pay no mind to the distant thunder, Beauty fills his head with wonder, boy".encode("utf-8").hex()
key =  "bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f489f3454bbe1cab4510ccb979013277a7bf"

def xor(a, b):
    return hex(int(a,16) ^ int(b,16))
print("Flag 6 :", xor(plaintext, key))

# M 0.7

tweet1 = bytes.fromhex('9b51325d75a7701a3d7060af62086776d66a91f46ec8d426c04483d48e187d9005a4919a6d58a68514a075769c97093e29523ba0')
tweet2 = bytes.fromhex('b253361a7a81731a3d7468a627416437c22f8ae12bdbc538df0193c581142f864ce793806900a6911daf213190d6106c21537ce8760265dd83e4')

def xor2(X, Y):
    return bytes(x ^ y for (x, y) in zip(X, Y))

start = b"flag{"
a = []
for i in range(0,len(tweet1), 5):
    x = xor2(tweet1[i:i+5], xor2(start, tweet2[i:i+5]))
    a.append(x)
    start = x
print("Flag 7 :", b"".join(a))

# M 0.8

from collections import Counter

ENGLISH_ALPHABET = b' abcdefghijklmnopqrstuvwxyz,.{}'
priority = ' etaoinshrdlcumwfgypbvkjxqz,.{}'

CHALLENGE_CIPHERTEXT = "4d68f21bf515dce57ee78a66724c4d9f5416fadc8d417652d8cbe1ce8080fc132bec643cc30460f9561669cc16d2786af846a12c611c6dc150504a22b18c95c9e34dd8f0efb1aa0fe0ec8a996b03ee56b27bac5bbc70413a5fa29de92dfee2802735e334c44f026e6cbbf9b40f65a0faf3bf11ddfb75083b417eb306f317c4f07bf88c27714555994045a9c8cf517042dccaf4c98e82a50336bc7836911325ea4b107e8942ce752fb450ba29660024da43045725ba8c9fc0ea52d6e0eeebf940effd8a997c03e405bb70e25eb138153d5ca29cf22dfee6837e23ac2dc5161c723ebbbce71862b3bfeabb0698a86a097e0465a012ea0dc4ea73fb9b746409559f5953fa899a42224fc4dbb5c4869eb41530e86921c55729e01e1d3bca59ca6562b646f86e650061c740044d6db6dfd4d1fb4099feefabbe5be9be80df281fe940f77ee940b23f473614a29cf22db0ad836637ab7fc259197473b1f5f71a63e5b8fdfe16c6ed7f157e4026b318ba0dcde132f48b77784c4b82524efd898054225a8cd3fac9808fb0002afd6e3cc51e23ae4d0679da42cf647aac5cbb20320b6dc54d415163ffcd8785e050dafaa6e5bc4ee2f6cfda6707f448b935ef58ab7057371ae39cee29bde6836374b436d55e55676cbaa4e11e63a6a3b8bf0cd5e46712725728f218f314cce873e58e7e3c094e9e5244ec898e127054d8d1e7879c9aae1523f12c3ad80728eb4c5376c855ce7961bd15bc2f614866d0404a0338acc99089b351d1fbf9e5b44af5f680dd2806e05cf774e055aa27152652e7c8fe2dbaf885733dac31815913216ab7b0b41768abbdecb642dbee3e0875406fa402fe0cc4e832e58d737f5b4ad81742e1cccf596348c5cdfececf8ba4112ff56238c51e2fe01e1a75df59ca666aab15b8217d036ddb42044522ad8c87d1e14cd7f5f9e5b649a1fd87d87a0ae251b267ff19b13854261ae39aff68ace8966235b73ac5161c6f3eabbdf15b6eacaaf0bb10c0ed6615350472ba0eba0ad1f67bf98574305a5199425aed898d57224fc4ccf0c2cf8db41130fd6f2dd40533ae521c75ce16c9622fb55aa62b320e6bc705504b28ffc98cc4fe4cd7f3feacb641a1ea80996a0ea156a276ef5cb623532756acc8ee20bbe3ca2720ab3a81521c726abebbf71e7ee5b8fdaa15d1ed7041784b68a10ef90cd1ed64f2c268734a4c844553e7ca8a412254ca9ee1cf8aceaf0430f5623ec25721fc5b5377c05dc37c76f841bb6e700d24d850485724afc091d6b34adfb2feadbc0fedfb81de7c03a14ab135f851a0705e3743f587e82cf0ad926f21b07fc75f1b6577b1b2b41662b7bfb8ac07c4ed7f157e4026a11fe810cbe361b78c66625b56814416edc6985c224fc4dbb5d7809daf1920f06979dd122ee94a1b688959c0307bb050f425771173da57400f6dacc59ac6f605cef7aaa6b841a1ea8ed26d4bf54db235eb4ba031413749f6c8f927b3e0896974a736d75f066e6cffbaf25b6ca9b6b8aa0ad1a87a08685067bc08ff0a8ba466ff8727624c58855858a9dd875b711bd8dbe6d3cf99b30229ef2c30c25734e65f073bc05086712faa50a42b731c61d10557573fb6c29385fc46dae7f8b6f946efbe9bd16d4bf149b67ce24da028417e1ae386fe68aae5832730aa2cd5571b627bffb7f10f7aa0bff6fe01dbfa6c04685469bc0ff317c2a471ff8375714a4d934545a9c09c12631bc1cbf9d3869eb01562f36a79c51f25ae551662de59d4742fb450ba2966002895514c466db4c98dd2fc57ddb2e6a0ad5be4ec9c997f02ed49f779e557a07040221aeb86ba3cb6e8c67435ae3a814114783ea8bce0132da7b5ecb642dbeb7d14695663bc08ff0a85eb74b7966f75094a82455fe7cec1126457cdd9eec19d8bad0527f26f2091162eef520a68c045867f61f847b13e770970d041044828a6df80d7f644d4ef"

challenges = [CHALLENGE_CIPHERTEXT[i:i+240] for i in range(0, len(CHALLENGE_CIPHERTEXT), 240)]
key = []

def find_key(i, c_len):
    a = []
    for c in challenges:
        a.append(c[i:i+2])
    a="".join(a)
    most_frequent_char = dict(Counter(a[idx : idx + 2] for idx in range(len(a) - 1)))
    most_frequent_char = {k: v for k, v in sorted(most_frequent_char.items(), key=lambda item: item[1], reverse=True)}
    
    for p in priority:
        for char in list(most_frequent_char.keys()):
            not_in = False
            kk = xor2(bytes.fromhex(p.encode("utf-8").hex()), bytes.fromhex(char))
            for z in range(c_len):
                if xor2(kk,bytes.fromhex(challenges[z][i:i+2])) not in ENGLISH_ALPHABET:
                    not_in = True
                    break
            if not_in == False:
                return kk

    
for i in range(0,len(challenges[len(challenges)-1])-1,2):
    key.append(find_key(i,len(challenges)))

for i in range(len(challenges[len(challenges)-1]),len(challenges[0]),2):
    key.append(find_key(i,len(challenges)-1))

key = b"".join(key)

res = []
for c in challenges:
    res.append(xor2(key,bytes.fromhex(c)))
print(b"".join(res))