import itertools
import multiprocessing
from Crypto.Hash import SHA1, HMAC
from string import ascii_lowercase

SALT = b'b49d3002f2a089b371c3'
HASH = 'd262db83f67a37ff672cf5e1d0dfabc696e805bc'


if __name__ == '__main__':
    combinations = itertools.product(reversed(ascii_lowercase), repeat=6)
    for combination in combinations:
        combination = ''.join(combination)
        h = HMAC.new(key=combination.encode(), msg=SALT, digestmod=SHA1).hexdigest()
        if h == HASH:
            print(combination)
            break