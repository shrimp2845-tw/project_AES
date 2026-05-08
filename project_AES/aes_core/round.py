from . import core_utils

def encrypt_round(state: list[int], rkey: list[int], last: bool = False, use_sbox: bool = True, custom_sbox: list[int] = None, use_mixcolumns: bool = True, use_shiftrow: bool = True) -> list[int]:
    if not len(state) == len(rkey) == 16:
        raise ValueError('encrypt_round: invalid data or key size')
    if use_sbox:
        state = core_utils.subbytes(state, custom_sbox)
    if use_shiftrow:
        state = core_utils.shiftrow(state)
    if not last and use_mixcolumns:
	    state = core_utils.mixcolumns(state)
    state = core_utils.add_rk(state, rkey)
    return state

def decrypt_round(state: list[int], rkey: list[int], last: bool = False, use_sbox: bool = True, custom_inv_sbox: list[int] = None, use_mixcolumns: bool = True, use_shiftrow: bool = True) -> list[int]:
    if not len(state) == len(rkey) == 16:
        raise ValueError('decrypt_round: invalid data or key size')
    if use_shiftrow:
        state = core_utils.inv_shiftrow(state)
    if use_sbox:
        state = core_utils.inv_subbytes(state, custom_inv_sbox)
    state = core_utils.add_rk(state, rkey)
    if not last and use_mixcolumns:
        state = core_utils.inv_mixcolumns(state)
    return state

def main():
    pass

if __name__ == "__main__":
    main()