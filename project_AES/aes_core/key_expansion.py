from .core_utils import sbox

RCI = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def split_block(data: list[int]) -> list[list[int]]:
    if len(data) % 4 != 0:
        raise ValueError('split_block: invalid data size')
    result = [data[i: i+4] for i in range(0, len(data), 4)]
    return result

def rotword(data: list[int]) -> list[int]:
    if len(data) != 4:
        raise ValueError('rotword: invalid data size')
    result = data[1:] + data[:1]
    return result

def subword(data: list[int]) -> list[int]:
    if len(data) != 4:
        raise ValueError('subword: invalid data size')
    result = [sbox(i) for i in data]
    return result

def rcon(round: int) -> int:
    if round > len(RCI) or round < 1:
        raise ValueError('rcon: invalid round')
    result = [RCI[round-1]] + [0x00] * 3
    return result

def key_expand(key: bytes) -> list[list[int]]:
    round_dict = {128: (10, 4),
                192: (12, 6),
                256: (14, 8)}
    key_length = len(key) * 8
    if not round_dict.get(key_length):
        raise ValueError('key_expand: invalid key size')
    rounds, nk = round_dict[key_length]
    total_words = (rounds+1) * 4
    key_list = list(key)
    ek = split_block(key_list)
    for i in range(nk, total_words):
        temp = ek[i-1][:]
        if i % nk == 0:
            temp = rotword(temp)
            temp = subword(temp)
            temp = [a ^ b for a, b in zip(temp, rcon(i // nk))]
        elif key_length == 256 and i % nk == 4:
            temp = subword(temp)
        new_word = [a ^ b for a, b in zip(ek[i-nk], temp)]
        ek.append(new_word)
    rks = []
    for i in range(rounds+1):
        rk = [j for k in ek[i*4: (i+1)*4] for j in k]
        rks.append(rk)
    return rks

def main():
    pass

if __name__ == "__main__":
    main()
