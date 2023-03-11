from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1

from Crypto.Util.Padding import pad, unpad

def byte_xor(ba1, ba2):
            return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

class StrangeCTR():
    def __init__(self, key: bytes, nonce : bytes = None, initial_value : int = 0, block_length: int = 16):
        """Initialize the CTR cipher.
        """

        if nonce is None:
            # Pick a random nonce
            nonce = get_random_bytes(block_length//2)

        self.nonce = nonce
        self.initial_value = initial_value
        self.key = key
        self.block_length = block_length

    def byte_xor(self, ba1, ba2):
            return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CTR mode:

        C_i = E_k(N || c(i)) xor P_i xor 1337

        Uses nonce, counter initial value and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext
        """

        ciphertext = b''
        plaintext = pad(plaintext, self.block_length)

        count = self.initial_value
        
        for i in range(0,len(plaintext), self.block_length):
            iv = self.nonce + count.to_bytes(self.block_length//2, "big")
            cipher = AES.new(self.key, AES.MODE_ECB)
            ciphertext += self.byte_xor(self.byte_xor(cipher.encrypt(iv), plaintext[i:i+self.block_length]), int.to_bytes(1337, self.block_length ,"big"))
            count += 1 
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CTR mode.

        Uses nonce, counter initial value and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """

        plaintext = b''
        count = self.initial_value
        for i in range(0, len(ciphertext), self.block_length):
            iv = self.nonce + count.to_bytes(self.block_length//2, "big")
            cipher = AES.new(self.key, AES.MODE_ECB)
            plaintext += self.byte_xor(self.byte_xor(cipher.encrypt(iv), ciphertext[i:i+self.block_length]), int.to_bytes(1337, self.block_length ,"big"))
            count += 1
        return unpad(plaintext, self.block_length)

def main():
    cipher = StrangeCTR(get_random_bytes(16))

    # Block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    m = pad(b'intro',16)
    c = bytes.fromhex('01f0ceb3dad5f9cd23293937c893e0ec')

    i = int.to_bytes(1337, 16 ,"big")
    r1 = byte_xor(byte_xor(m,c),i)
    flag_enc = byte_xor(pad(b'flag',16),r1)

    print(byte_xor(flag_enc,i).hex())



    # assert cipher.encrypt(b'intro').hex() == '01f0ceb3dad5f9cd23293937c893e0ec'
    

    

if __name__ == "__main__":
    main()
