from dataclasses import dataclass

@dataclass
class AESConfig:
    use_sbox: bool = True
    use_mixcolumns: bool = True
    custom_sbox: list | None = None
    use_shiftrow: bool = True
    use_log: bool = False
    progress_bar: bool = False
    def __post_init__(self):
        if not self.use_sbox and self.custom_sbox is not None:
            raise ValueError("custom_sbox requires use_sbox=True")
            

    

