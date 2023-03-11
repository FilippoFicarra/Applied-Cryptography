from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1

from Crypto.Util.Padding import pad, unpad


class StrangeCBC():
    def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
        """Initialize the CBC cipher.
        """

        if iv is None:
            # TODO: Pick a random IV
            iv = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")

        self.iv = iv
        self.key = key
        self.block_length = block_length
    def byte_xor(self, ba1, ba2):
            return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
        
        
        c_i_m_1 = self.iv
        ciphertext = b''
        plaintext = pad(plaintext, self.block_length)
        
        for i in range(0,len(plaintext), self.block_length):
            cipher = AES.new(self.key, AES.MODE_ECB)
            c_i = cipher.encrypt(self.byte_xor(self.byte_xor(plaintext[i:i+self.block_length], c_i_m_1),int.to_bytes(1336, self.block_length ,"big")))
            ciphertext += c_i
            c_i_m_1 = c_i
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        plaintext = b''
        iv = self.iv
        for i in range(0, len(ciphertext), self.block_length):
            cipher = AES.new(self.key, AES.MODE_ECB)
            p_i = self.byte_xor(self.byte_xor(cipher.decrypt(ciphertext[i:i+self.block_length]), iv),int.to_bytes(1336, self.block_length ,"big"))
            plaintext += p_i
            iv = ciphertext[i:i+self.block_length]

        return unpad(plaintext, self.block_length)

def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt
       

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    print("Now it starts")

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv  = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
            "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
            "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
            "3fd46234ff7b62ad365d1db13bb249721b")
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")

if __name__ == "__main__":
    main()
