def add_padding(file: bytes, block_length: int = 16) -> bytes:
    """
    add padding to a bytes string, following
    PKCS#7
    """
    if block_length >= 256 or 0 >= block_length:
        raise ValueError('add_padding: invalid block size')
    if len(file) % block_length == 0:
        return file + block_length.to_bytes(1, 'big') * block_length
    return file + bytes([block_length-(len(file)%block_length)] * (block_length-(len(file)%block_length)))

def remove_padding(file: bytes, block_length: int = 16) -> bytes:
    """
    remove padding from a bytes string, following
    PKCS#7
    """
    if not isinstance(file, bytes):
        raise TypeError
    pl = file[-1]
    if pl > block_length or pl < 1 or file[-pl:] != bytes([pl])*pl:
        raise ValueError('remove_padding: invalid padding')
    return file[:-pl]

def main():
    pass

if __name__ == "__main__":
    main()