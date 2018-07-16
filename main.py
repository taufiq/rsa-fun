import os
from Crypto.PublicKey import RSA

pub_key_filenames = list(filter(lambda x: x.endswith(".pem"), os.listdir("./challenge")))
pub_keys = []

os.chdir('challenge')

for name in pub_key_filenames:
    key_text = open(name, 'r').read()
    pub_key = RSA.importKey(key_text)
    print(f'{pub_key_filenames.index(name) }: ' , pub_key.n, f'e: {pub_key.e}')
    pub_keys.append(pub_key)

#GCD where a is the larger number
def gcd(a, b):
    if b == 0:
        return a
    else:
        a %= b
    return gcd(b, a)

print(gcd(978, 89798763754892653453379597352537489494736))