#!/usr/bin/env python

from Crypto.Hash import SHA256


class Solution():
    def __init__(self):
        pass

    def eight_byte_encoding(self, string: str):
        # The octet string AL is equal to the number of bits in string expressed as a 64-bit unsigned integer in network byte order.
        n_bits = len(string)*8 
        return n_bits.to_bytes(8, byteorder='big').hex()

def main():
    sol = Solution()
    strings = ['a', 'a 23 bytes long string', '64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes']
    flag = []
    for string in strings:
        flag.append(sol.eight_byte_encoding(string))
    print(','.join(flag))

if __name__ == "__main__":
    main()
