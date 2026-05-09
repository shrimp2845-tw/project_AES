from project_AES import AES
from project_AES.configs import AESConfig
import hashlib

TEST_DATA = """I could never find the right way to tell you
Have you noticed I've been gone?
'Cause I left behind the home that you made me
But I will carry it along
And it's a long way forward, so trust in me
I'll give them shelter, like you've done for me
And I know, I'm not alone, you'll be watching over us
Until you're gone
When I'm older, I'll be silent beside you
I know words won't be enough
And they won't need to know the names or our faces
But they will carry on for us
And it's a long way forward, so trust in me
I'll give them shelter, like you've done for me
And I know, I'm not alone, you'll be watching over us
Until you're gone
Oh it's a long way forward, trust in me
I'll give them shelter, like you've done for me
And I know, I'm not alone, you'll be watching over us
Until
"""

def sha256(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()

def encrypt_data(key: str, plaintext: bytes, mode: str, conf):
    cipher = AES(sha256(key)[:16], mode=mode, config=conf)
    return cipher.encrypt(plaintext)

def decrypt_data(key: str, ciphertext: bytes, mode: str, conf):
    cipher = AES(sha256(key)[:16], mode=mode, config=conf)
    return cipher.decrypt(ciphertext)

def main(mode):
    key = 'ThisIsATestKey'
    original_data = TEST_DATA.encode()
    conf = AESConfig(progress_bar=True, use_log=True)
    print(f'__________mode {mode.upper()}:__________')
    encrypted = encrypt_data(key, original_data, mode, conf)
    decrypted = decrypt_data(key, encrypted, mode, conf)
    h1 = hashlib.md5(original_data).hexdigest()
    h2 = hashlib.md5(decrypted).hexdigest()
    print('decrypted text:')
    print(decrypted.decode()[:60]+'......')
    print('hash check:', h1 == h2)
    print(h1)
    print(h2)

if __name__ == "__main__":
    cases = ['ecb', 'cbc', 'ctr']
    for mode in cases:
        main(mode)