import os
import gmpy2
from Crypto.PublicKey import RSA
from itertools import combinations
from decimal import Decimal

pub_key_filenames = list(filter(lambda x: x.endswith(".pem"), os.listdir("./challenge")))
pub_keys = []
key_pair_combs = []

os.chdir('challenge')

for name in pub_key_filenames:
    key_text = open(name, 'r').read()
    pub_key = RSA.importKey(key_text)
    # print(f'{pub_key_filenames.index(name) }: ' , pub_key.n, f'e: {pub_key.e}')
    pub_keys.append(pub_key)

# Possible combinations of indices of public keys
key_pair_combs = list(combinations(pub_keys, 2))
#GCD where a is the larger number
def gcd(a, b):
    if b == 0:
        return a
    else:
        a %= b
    return gcd(b, a)

compromised_key_pairs = []
compromised_keys_file_names = []
for key_pair in key_pair_combs:
    first_key, second_key = key_pair[0], key_pair[1]
    hcf = gcd(first_key.n, second_key.n)
    if hcf != 1:
        compromised_key_pairs.append(key_pair + (hcf, ))
        compromised_keys_file_names.append(pub_key_filenames[pub_keys.index(key_pair[0])])
        compromised_keys_file_names.append(pub_key_filenames[pub_keys.index(key_pair[1])])


private_keys = []
for pair in compromised_key_pairs:
    # q for first and second Key
    fsq = pair[2]
    first_key, second_key = pair[0], pair[1]
    # p for first Key
    fp =  gmpy2.div(first_key.n , hcf)
    f_phi_n = gmpy2.mul(fp - 1, fsq - 1)
    f_d = gmpy2.invert(first_key.e, f_phi_n)
    # p for second key
    sp =  gmpy2.div(second_key.n , hcf)
    s_phi_n = gmpy2.mul(sp - 1, fsq - 1)
    s_d = gmpy2.invert(second_key.e, s_phi_n)

    f_priv = RSA.construct((first_key.n, first_key.e, int(f_d), int(fp), int(fsq)))
    s_priv = RSA.construct((second_key.n, second_key.e, int(s_d), int(sp), int(fsq)))
    private_keys.append(f_priv)
    private_keys.append(s_priv)
    

# Saving private keys
private_key_path = "priv_keys/"
if not os.path.exists(private_key_path):
    os.mkdir(private_key_path)

dec_file_path = "dec_files/"
if not os.path.exists(dec_file_path):
    os.mkdir(dec_file_path)
    
for i, k in enumerate(private_keys):
    enc_filename = str(compromised_keys_file_names[i]).replace(".pem", ".bin")
    plaintext = ""
    with open(enc_filename, 'rb') as enc_b:
        cipher = enc_b.read()
        plaintext = k.decrypt(cipher)
    with open(dec_file_path + enc_filename.replace(".bin", "_dec.txt"), 'wb') as wr:
        wr.write(plaintext)

    private_key_filename = private_key_path + str(compromised_keys_file_names[i]).replace(".pem", "") + "_pub.pem"
    with open(private_key_filename, 'wb') as wr:
        wr.seek(0)
        wr.write(k.exportKey())

    