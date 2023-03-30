from Crypto.Hash import MD5
import tqdm
h = '9fb7009f8a9b4bc598b4c92c91f43a2c'


with open('/Users/filippoficarra/Documents/GitHub/Applied-Cryptography/Challenges/Week 5/M2/rockyou.txt', 'r') as file:
    file_contents = file.read()

for line in file_contents.splitlines():
    if MD5.new(line.encode()).hexdigest() == h:
        print("password: ", line)
        break