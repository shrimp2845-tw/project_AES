
def xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gfm(a: int, b: int) -> int:
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

def main():
    pass

if __name__ == "__main__":
    main()