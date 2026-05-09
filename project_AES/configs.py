from dataclasses import dataclass

@dataclass
class AESConfig:
    """
    Configuration for customizing the AES algorithm

    Arg:
        use_sbox (bool): enable/disable the SubBytes transformation. Defaults to True.
        use_mixcolumns (bool): Enable/disable the MixColumns transformation. Defaults to True.
        custom_sbox (list | None): A user-defined substitution table (256 integers).
            Requires `use_sbox` to be True. Defaults to None.
        use_shiftrow (bool): Enable/disable the ShiftRows transformation. Defaults to True.
        use_log (bool): If True, logs the state of dataflow for futher analysis.
        progress_bar (bool): If True, displays a progress bar during process.
        rounds(int | None): If True, use chosen round to encrypt/decrypt. Must be smaller than default rounds.
    """
    use_sbox: bool = True
    use_mixcolumns: bool = True
    custom_sbox: list | None = None
    use_shiftrow: bool = True
    use_log: bool = False
    progress_bar: bool = False
    rounds: int | None = None
    def __post_init__(self):
        if not self.use_sbox and self.custom_sbox is not None:
            raise ValueError("custom_sbox requires use_sbox=True")
