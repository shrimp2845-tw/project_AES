import os
import random
from project_AES import AES
from project_AES.configs import AESConfig
from project_AES import block_utils


class Vulnerable_AES:
    def __init__(self, secret=os.urandom(random.randint(30, 150)).hex()):
        self.__secret = secret
        self.__cipher = AES(os.urandom(16), mode='cbc')

    def get_encrypted_secret(self):
        return self.__cipher.encrypt(bytes.fromhex(self.__secret)).hex()

    def check_your_secret(self, ct: str):
        try:
            if self.__cipher.decrypt(bytes.fromhex(ct)).hex() == self.__secret:
                return 'ohhi!'
            else:
                return 'ohhi?'
        except Exception as e:
            return f'error : {e}'

    def check_raw(self, raw):
        if raw == self.__secret:
            print('how is this possible!!! QAQ')
        else:
            print('awa why so weak')


def xor(b1: bytes, b2: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(b1, b2))


def get_info(s):
    res = []
    for i in range(len(s) // 32):
        res.append(s[i * 32: i * 32 + 32])
    return res


def find_valid_padding(r, c, idx):
    c = bytes.fromhex(c)
    if target.check_your_secret((r + c).hex()) == 'error : remove_padding: invalid padding' and idx != 0:
        print('error')
        raise
    if idx != 0:
        nr = r[:16 - idx] + xor(xor(r[16 - idx:], (idx.to_bytes()) * idx), ((idx + 1).to_bytes()) * idx)
    else:
        nr = r
    for i in range(256):
        nb = xor(nr, i.to_bytes().rjust(16 - idx, b'\x00') + (b'\x00' * idx))
        if target.check_your_secret((nb + c).hex()) != 'error : remove_padding: invalid padding':
            return nb
    return 'done'


def check_padding_len(r, c):
    c = bytes.fromhex(c)
    if target.check_your_secret((r + c).hex()) == 'error : remove_padding: invalid padding':
        return 0
    for i in range(16):
        nr = r[:i] + xor((1).to_bytes(), r[i].to_bytes()) + r[i + 1:]
        if target.check_your_secret((nr + c).hex()) == 'error : remove_padding: invalid padding':
            return 16 - i
    return 'done'


def attack_block(block, iv):
    idx = 0
    n = bytes.fromhex('0' * 32)
    while True:
        n = find_valid_padding(n, block, idx)
        print(f'round:{idx}', n.hex())
        if idx == 15:
            re = xor(n, b'\x10' * 16).hex()
            print("result =", xor(bytes.fromhex(re), bytes.fromhex(iv)).hex())
            return xor(bytes.fromhex(re), bytes.fromhex(iv)).hex()
        if idx == 0:
            idx = check_padding_len(n, block)
        else:
            idx += 1


secret = """it's a long way forward, trust in me
I'll give them shelter, like you've done for me
And I know, I'm not alone, you'll be watching over us
Until......"""
target = Vulnerable_AES(secret=secret.encode().hex())


def main():
    print(target.check_your_secret(target.get_encrypted_secret()))
    blocks = get_info(target.get_encrypted_secret())
    iv, blocks = blocks[0], blocks[1:]
    print('iv:', iv)
    v = iv
    plaintext = []
    for j, i in enumerate(blocks):
        print(f'-----------------------block {j + 1}-----------------------')
        plaintext.append(attack_block(i, v))
        v = i
    pl = block_utils.remove_padding(bytes.fromhex(''.join(plaintext)))
    print('ans: ', pl.decode())
    print('check:')
    target.check_raw(pl.hex())


if __name__ == '__main__':
    main()
