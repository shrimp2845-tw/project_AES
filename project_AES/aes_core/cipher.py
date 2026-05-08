from project_AES.configs import CoreConfig, DEFAULT_CORE
from . import key_expansion, core_utils, round

class CoreAES:
    def  __init__(self, key: bytes, config: CoreConfig = DEFAULT_CORE):
        self.original_key = key
        key_length = len(self.original_key) * 8
        round_dict = {128: 10, 
                192: 12, 
                256: 14}
        if not round_dict.get(key_length):
            raise ValueError('CoreAES initialize: invalid key size')
        self.rounds = round_dict[key_length]
        self.round_keys = key_expansion.key_expand(key)
        self.use_sbox = config.use_sbox
        self.custom_sbox = config.custom_sbox
        self.use_log = config.use_log
        if self.custom_sbox:
            self.custom_inv_sbox = self.generate_inv_sbox(self.custom_sbox)
        else:
            self.custom_inv_sbox = None
        self.use_mixcolumns = config.use_mixcolumns
        self.use_shiftrow = config.use_shiftrow
    
    def encrypt_block(self, block: bytes) -> bytes | tuple[bytes, dict]:
        if len(block) != 16:
            raise ValueError('encrypt_block: invalid block size')
        if self.use_log:
            log = {'mode': 'encrypt',
                   'input': block.hex(),
                   'key': self.original_key,
                   'round_keys': self.round_keys,
                   'dataflow': []}
        state = list(block)
        for i in range(self.rounds+1):
            round_key = self.round_keys[i]
            if self.use_log:
                log['dataflow'].append(bytes(state).hex())
            if i == 0:
                state = core_utils.add_rk(state, round_key) 
            else:
                state = round.encrypt_round(state, round_key, 
                            last = (i == self.rounds), 
                            use_sbox = self.use_sbox, 
                            custom_sbox = self.custom_sbox, 
                            use_mixcolumns = self.use_mixcolumns, 
                            use_shiftrow = self.use_shiftrow)
        result = bytes(state)
        if self.use_log:
            log['output'] = result
            return result, log
        return result       
    
    def decrypt_block(self, block: bytes) -> bytes | tuple[bytes, dict]:
        if len(block) != 16:
            raise ValueError('decrypt_block: invalid block size')
        if self.use_log:
            log = {'mode': 'decrypt',
                   'input': block.hex(),
                   'key': self.original_key,
                   'round_keys': self.round_keys,
                   'dataflow': []}
        state = list(block)
        for i in range(self.rounds+1):
            round_key = self.round_keys[-(i+1)]
            if self.use_log:
                log['dataflow'].append(bytes(state).hex())
            if i == 0:
                state = core_utils.add_rk(state, round_key)
            else:
                state = round.decrypt_round(state, round_key, 
                            last = (i == self.rounds), 
                            use_sbox = self.use_sbox, 
                            custom_inv_sbox = self.custom_inv_sbox, 
                            use_mixcolumns = self.use_mixcolumns, 
                            use_shiftrow = self.use_shiftrow)
        result = bytes(state)
        if self.use_log:
            log['output'] = result
            return result, log       
        return result
    
    @staticmethod
    def generate_inv_sbox(box: list[int]) -> list[int]:
        if len(box) != 256:
            raise ValueError('generate_inv_sbox: invalid box size')
        inv_sbox = [0] * 256
        for i in range(256):
            output_val = box[i]
            inv_sbox[output_val] = i  
        return inv_sbox
            
def main():
    pass

if __name__ == "__main__":
    main()