from project_AES import AES
from project_AES.configs import AESConfig
import time
import hashlib

def sha256(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()
    
def read_bytes(name, l = 0):
    bfile = open(name, 'rb')
    data = bfile.read()
    bfile.close()
    if l == 0:
        return data
    return data[:l]

def write_bytes(name, data):
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
    
    
def main(m):
    k1 = 'ThisIsATestKey'
    k2 = 'ThisIsAnotherTestKey'
    k = k1
    n1 = 'mahiru.png'
    n2 = 'shelter.txt'
    name = n2
    conf = AESConfig(progress_bar = True, use_log = False)
    encrypt(k, name, name+'.bin', m, conf)
    decrypt(k, name+'.bin', name.split('.')[0]+'2.'+name.split('.')[1], m, conf)
    h1, h2 = hashlib.md5(read_bytes(name)).hexdigest(), hashlib.md5(read_bytes(name.split('.')[0]+'2.'+name.split('.')[1])).hexdigest()
    print('md5', h1 == h2)
    print(h1)
    print(h2)
    

if __name__ == "__main__":
    case = ['ecb', 'cbc', 'ctr']
    for i in case:
        main(i)