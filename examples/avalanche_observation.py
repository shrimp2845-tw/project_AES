import os
from tqdm import tqdm
from project_AES import AES
from project_AES.configs import AESConfig

STANDARD = AESConfig()
NO_SBOX = AESConfig(use_sbox = False)
NO_MIXCOLUMNS = AESConfig(use_mixcolumns = False)
NO_SHIFTROW = AESConfig(use_shiftrow = False)

def bytes_to_bits(byd: bytes) -> list[int]:
    return [int(bit) for byte in byd for bit in format(byte, '08b')]

def bits_to_bytes(bits: list[int]) -> bytes:
    return bytes(int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8))

def compare(a: bytes, b: bytes) -> float:
    total, different = 0, 0
    for i, j in zip(bytes_to_bits(a), bytes_to_bits(b)):
        total += 1
        if i != j:
            different += 1
    return different/total
    
def flip_bit(data: bytes, index: int = 0) -> bytes:
    bits = bytes_to_bits(data)
    bits[index] ^= 1
    return bits_to_bytes(bits)
    
def observate(config: AESConfig, key_len: int = 128):
    if key_len not in (128, 192, 256):
        raise ValueError
    cipher = AES(os.urandom(key_len//8), config = config)
    total = 0
    for i in range(50):
        rpt1 = os.urandom(16)
        rpt2 = flip_bit(rpt1)
        total += compare(cipher.encrypt_block(rpt1), cipher.encrypt_block(rpt2))
    return total/50
    
def test(conf, key_len: int = 128):
    total = 0
    for i in tqdm(range(100)):
        p = observate(conf, key_len)
        total += p
    return total/100
    
def main():
    test_cases = [STANDARD, NO_SBOX, NO_MIXCOLUMNS, NO_SHIFTROW]
    for i in test_cases:
        print('_'*30)
        print(f'Test Avalance: \n{i} : \n{test(i)}')

if __name__ == "__main__":
    main()