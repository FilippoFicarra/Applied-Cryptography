#!/usr/bin/env python
import secrets
from Crypto.Hash import SHA384, HMAC
from Crypto.Cipher import AES 


class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = mac_key_len

        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")
        
        self.mac_key = key[:mac_key_len]
        self.enc_key = key[-enc_key_len:]

        self.block_len = 16

    def _add_pt_padding(self, pt: bytes):
        """Return padded plaintext"""
        plen = len(pt)%self.block_len
        if plen == 0:
            plen = self.block_len
        return pt + bytes([plen]) * plen

    def _remove_pt_padding(self, pt: bytes):
        """Return unpadded plaintext"""
        plen = pt[-1]
        if not plen in range(1, self.block_len + 1):
            raise ValueError("Bad decryption")
        return pt[:-plen]
    
    def eight_byte_encoding(self, string: str):
        # The octet string AL is equal to the number of bits in string expressed as a 64-bit unsigned integer in network byte order.
        n_bits = len(string)*8 
        return n_bits.to_bytes(8, byteorder='big').hex()

    def encrypt(self, pt: bytes, add_data: bytes = b'', iv: bytes = None):
        """Compute ciphertext and MAC tag.

        Keyword arguments:
        pt       -- plaintext
        add_data -- additional data
        iv       -- initialization vector
        """
        if iv is None:
            # Choose random IV.
            iv = secrets.token_bytes(self.block_len)
        
        self.cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)

        # Compute ciphertext.
        ct = self.cipher.encrypt(self._add_pt_padding(pt))
        tag = HMAC.new(key = self.mac_key, msg = add_data + (iv + ct) + bytes.fromhex(self.eight_byte_encoding(add_data)), digestmod=SHA384).digest()[:self.tag_len]

        return (iv + ct) + tag
    
    def decrypt(self, ct: bytes, add_data: bytes = b''):
        """Verify MAC tag and return plaintext.
        """

        print(ct.hex())
        iv = ct[:self.block_len]
        ct = ct[self.block_len:]
        tag = ct[-self.tag_len:]
        ct = ct[:-self.tag_len]
        print(iv.hex())
        print(ct.hex())
        print(tag.hex())
        if not HMAC.new(key = self.mac_key, msg = add_data + (iv + ct) + bytes.fromhex(self.eight_byte_encoding(add_data)), digestmod=SHA384).digest()[:self.tag_len] == tag:
            raise ValueError("Bad decryption")
        self.cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)
        pt = self.cipher.decrypt(ct)
        return pt

def main():
    test_key = bytes.fromhex("""
        41206c6f6e6720726561642061626f75742073797374656d64206973207768617420796f75206e65656420616674657220746865206c6162
        """)
    test_ct = bytes.fromhex("""
        bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78
        aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1
        b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab
        7df30af4ad0db52e
        """)
    test_ad = bytes.fromhex("")
    print(CBC_HMAC(32, 24, test_key).decrypt(test_ct, test_ad))


if __name__ == "__main__":
    main()
