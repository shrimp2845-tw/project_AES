from . import core_utils

def encrypt_round(state: list[int], rkey: list[int], last: bool = False, use_sbox: bool = True, custom_sbox: list[int] = None, use_mixcolumns: bool = True, use_shiftrow: bool = True) -> list[int]:
    """
    Performs one encryption round of a block cipher (AES-like)
    
    Args:
        state (list[int]): A 16-byte list representing the current AES state.
        rkey (list[int]): A 16-byte list representing the round key.
        last (bool): If True, the MixColumns step is skipped (final round).
        use_sbox (bool): Whether to perform the SubBytes transformation.
        custom_sbox (list[int], optional): A custom S-box lookup table. Defaults to None.
        use_mixcolumns (bool): Whether to perform the MixColumns transformation.
        use_shiftrow (bool): Whether to perform the ShiftRows transformation.
    
    Returns:
        list[int]: The transformed 16-byte state after the encryption round.
    
    """
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
    """
    Performs one round of AES decryption.

    Args:
        state (list[int]): A 16-byte list representing the current AES state.
        rkey (list[int]): A 16-byte list representing the round key.
        last (bool): If True, denotes the first decryption round which InvMixColumns is skipped.
        use_sbox (bool): Whether to perform the InvSubBytes transformation.
        custom_inv_sbox (list[int], optional): A custom inverse S-box lookup table, Defaults to None.
        use_mixcolumns (bool): Whether to perform the InvMixColumns transformation.
        use_shiftrow (bool): Whether to perform the InvShiftRows transformation.

    Returns:
        list[int]: The transformed 16-byte state after the decryption round.
    """
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
