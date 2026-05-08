
def xtime(a: int) -> int:
    """perform a × 2 within GF(2⁸)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gfm(a: int, b: int) -> int:
    """preform a × b within GF(2⁸)"""
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result
