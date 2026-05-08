import os
from datetime import datetime
import json
from .block_utils import add_padding, remove_padding, split_data, merge_data
from .configs import AESConfig
from .aes_core.cipher import CoreAES
from tqdm import tqdm

class AES:
    def __init__(self, key: bytes, mode: str = 'ECB', config: AESConfig = AESConfig()):
        self.modes = {'ECB': self.__ecb,
                            'CBC': self.__cbc, 
                            'CTR': self.__ctr}
        if mode.upper() not in self.modes:
            raise ValueError('AES initialize: unknown mode of operation')
        self.cipher = CoreAES(key, config = config)
        self.use_log = config.use_log
        self.progress_bar = config.progress_bar
        self.mode = mode.upper()
        self.mode_func = self.modes[self.mode]
        self.log_path = './projectAES_log/'
        if not os.path.exists(self.log_path):
            os.mkdir(self.log_path)
                  
    def __ecb(self, data: list[bytes], decrypt: bool = False) -> tuple[list[bytes], list[dict] | None]:      
        if decrypt:
            method = 'decrypt'
        else:
            method = 'encrypt'
        log = {'method': method,
                'mode': self.mode, 
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'input': [i.hex() for i in data],               
                'actions': []} 
        que = data
        if self.progress_bar:
            que = tqdm(que)
        result = []                       
        for i, j in enumerate(que):
            if not decrypt:
                nb = self.cipher.encrypt_block(j)
            else:
                nb = self.cipher.decrypt_block(j)
            if self.use_log:
                nb, block_log = nb
                log['actions'].append(block_log)
            result.append(nb)
        if self.use_log:
            log['output'] = [i.hex() for i in result]
            return result, log
        return result, None
                 
    def __cbc(self, data: list[bytes], decrypt: bool = False) -> tuple[list[bytes], list[dict] | None]:
        if decrypt:
            method = 'decrypt'
        else:
            method = 'encrypt'
        log = {'method': method,
                'mode': self.mode, 
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'input': [i.hex() for i in data],               
                'actions': []} 
        que = data
        if self.progress_bar:
            que = tqdm(que)
        result = []
        xor = self.__xor
        if not decrypt:
            iv = os.urandom(16)
            if self.use_log:
                log['iv'] = iv.hex()
            v = iv
            for i, j in enumerate(que):
                temp = self.cipher.encrypt_block(xor(j, v))               
                if self.use_log:
                    nb, block_log = temp
                    log['actions'].append({'method': 'xor', 'input': (j.hex(), v.hex()), 'output': nb.hex()})
                    log['actions'].append(block_log)
                else:
                    nb = temp
                result.append(nb)
                v = nb
            result = [iv] + result
            if self.use_log:
                log['actions'].append({'method': 'connect', 'input': ([result[0].hex()], [i.hex() for i in result[1:]]), 'output': [i.hex() for i in result]})
                return result, log
            return result, None
        else:
            for i, j in enumerate(que):
                if i == 0:
                    v = j
                    if self.use_log:
                        log['actions'].append({'method': 'get iv', 'output': v.hex()})
                    continue
                temp = self.cipher.decrypt_block(j)
                if self.use_log:
                    nb, block_log = temp
                    log['actions'].append(block_log)
                else:
                    nb = temp
                nb = xor(nb, v)
                if self.use_log:
                    log['actions'].append({'method': 'xor', 'input': (temp[0].hex(), v.hex()), 'output': nb.hex()})
                result.append(nb)
                v = j
            if self.use_log:
                log['output'] = [i.hex() for i in result]
                return result, log
            return result, None
                   
    def __ctr(self, data: list[bytes], decrypt: bool = False) -> tuple[list[bytes], list[dict] | None]:
        if not decrypt:
            pass
        else:
            pass
        
    def encrypt(self, data: bytes) -> bytes:
        blocks = split_data(add_padding(data))
        result, log = self.mode_func(blocks)
        if self.use_log:
            with open(f'{self.log_path}log{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.json', 'w') as f:
                json.dump(log, f)
        return merge_data(result)
        
    def decrypt(self, data: bytes) -> bytes:
        blocks = split_data(data)
        result, log = self.mode_func(blocks, decrypt = True)
        if self.use_log:
            with open(f'{self.log_path}log{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.json', 'w') as f:
                json.dump(log, f)
        return remove_padding(merge_data(result))
    
    @staticmethod
    def __xor(b1: bytes, b2: bytes):
        return bytes(i^j for i, j in zip(b1, b2))

def main():
    pass

if __name__ == "__main__":
    main()