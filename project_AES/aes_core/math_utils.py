from functools import cache

def xtime(a: int) -> int:
    """perform a × 2 within GF(2⁸)."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def xtime128(a: int) -> int:
    """perform a × 2 within GF(2¹²⁸)"""
    msb = a & (1 << 127)
    a <<= 1
    if msb:
        a ^= 0xE1000000000000000000000000000000
    return a & ((1 << 128) - 1)
    
@cache
def gfm(a: int, b: int) -> int:
    """preform a × b within GF(2⁸)"""
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result

def gfm128(a: int, b: int) -> int:
    """preform a × b within GF(2¹²⁸)"""
    result = 0
    for i in range(128):
        if b & 1:
            result ^= a
        a = xtime128(a)
        b >>= 1
    return result