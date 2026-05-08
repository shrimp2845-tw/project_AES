def add_padding(file: bytes, block_length: int = 16) -> bytes:
    """
    add padding to a bytes string, using standard
    PKCS#7 method
    """
    if block_length >= 256 or 0 >= block_length:
        raise ValueError('add_padding: invalid block size')
    if len(file) % block_length == 0:
        return file + block_length.to_bytes(1, 'big') * block_length
    return file + bytes([block_length-(len(file)%block_length)] * (block_length-(len(file)%block_length)))

def remove_padding(file: bytes, block_length: int = 16) -> bytes:
    """
    remove padding from a bytes string using standard
    PKCS#7 method
    """
    if not isinstance(file, bytes):
        raise TypeError
    pl = file[-1]
    if pl > block_length or pl < 1 or file[-pl:] != bytes([pl]) * pl:
        raise ValueError('remove_padding: invalid padding')
    return file[:-pl]

def split_data(file: bytes, length: int = 16) -> list[bytes]:
    if (len(file)%length) != 0:
        raise ValueError ('split_data: data must be splited perfectly')
    return [file[i: i+length] for i in range(0, len(file), length)]
        
def merge_data(blocks: list[bytes]) -> bytes:
    return b''.join(blocks)
        
def main():
    pass

if __name__ == "__main__":
    main()