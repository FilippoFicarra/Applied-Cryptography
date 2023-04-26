#!/usr/bin/env python

from Crypto.Hash import SHA256


class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = 256

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


def main():
    aead = CBC_HMAC(16, 16, b''.join(bytes([i]) for i in range(32)))
    pt = b"Just plaintext\x02\x00"
    assert aead._remove_pt_padding(aead._add_pt_padding(pt)) == pt
    print(SHA256.new(data=aead._add_pt_padding(pt)).hexdigest())

if __name__ == "__main__":
    main()
