import os
from project_AES import AES
from project_AES.configs import AESConfig
import hashlib
import time

"""
Warning:
This example is for demonstrating module functionality
only and does not guarantee the security of encrypted data.
"""

PATH = "./test_files/"

def sha256(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()

def read_bytes(name: str, l = 0) -> str:
    bfile = open(name, 'rb')
    data = bfile.read()
    bfile.close()
    if l == 0:
        return data
    return data[:l]

def write_bytes(name, data) -> str:
    bfile = open(name, 'wb')
    bfile.write(data)
    bfile.close()

def encrypt(key: str, name: str, new_name: str, m: str, con):
    c = AES(sha256(key)[:16], mode = m, config = con)
    data = read_bytes(name)
    cdata = c.encrypt(data)
    write_bytes(new_name, cdata)
    print(f'successfully encrypted {name} with {key} and saved it as {new_name}')

def decrypt(key: str, name: str, new_name: str, m: str, con):
    c = AES(sha256(key)[:16], mode = m, config = con)
    data = read_bytes(name)
    cdata = c.decrypt(data)
    write_bytes(new_name, cdata)
    print(f'successfully decrypted {name} with {key} and saved it as {new_name}')

def main():
    if not os.path.exists(PATH):
        os.makedirs(PATH)
    config = AESConfig(progress_bar = True)
    ed = input('encrypt or decrypt? (e or d)')
    if ed == 'e':
        p = input('plaintext file name: ')
        n = input('name for encrypted file: ')
        k = input('key: ')
        m = input('mode: ')
        p, n = PATH+p, PATH+n
        t = time.time()
        encrypt(k, p, n, m, config)
        print('\ntime spent:', round(time.time()-t, 2),'sec')

    else:
        c = input('ciphertext file name: ')
        n = input('name for decrypted file: ')
        k = input('key: ')
        m = input('mode: ')
        c, n = PATH+c, PATH+n
        t = time.time()
        decrypt(k, c, n, m, config)
        print('\ntime spent:', round(time.time()-t, 2),'sec')

if __name__ == "__main__":
    main()
