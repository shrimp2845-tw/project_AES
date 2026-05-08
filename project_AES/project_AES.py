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
        if self.use_log:
            for i, j in enumerate(que):
                if not decrypt:
                    nb, block_log= self.cipher.encrypt_block(j)
                else:
                    nb, block_log= self.cipher.decrypt_block(j)           
                log['actions'].append(block_log)
                result.append(nb)            
            log['output'] = [i.hex() for i in result]
            return result, log
        else:
            for i, j in enumerate(que):
                if not decrypt:
                    nb = self.cipher.encrypt_block(j)
                else:
                    nb = self.cipher.decrypt_block(j)                
                result.append(nb)                  
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
        if self.use_log:
            if not decrypt:
                iv = os.urandom(16)
                log['iv'] = iv.hex()
                v = iv
                for i, j in enumerate(que):
                    nb, block_log = self.cipher.encrypt_block(xor(j, v))
                    log['actions'].append({'method': 'xor', 'input': (j.hex(), v.hex()), 'output': nb.hex()})
                    log['actions'].append(block_log)
                    result.append(nb)
                    v = nb
                result = [iv] + result
                log['actions'].append({'method': 'connect', 'input': ([result[0].hex()], [i.hex() for i in result[1:]]), 'output': [i.hex() for i in result]})
                return result, log               
            else:
                for i, j in enumerate(que):
                    if i == 0:
                        v = j
                        log['actions'].append({'method': 'get iv', 'output': v.hex()})
                        continue    
                    nb, block_log = self.cipher.decrypt_block(j)
                    log['actions'].append(block_log)
                    xb = xor(nb, v)
                    log['actions'].append({'method': 'xor', 'input': (nb.hex(), v.hex()), 'output': xb.hex()})
                    result.append(xb)
                    v = j
                log['output'] = [i.hex() for i in result]
                return result, log
        else:
            if not decrypt:
                iv = os.urandom(16)
                v = iv
                result = [iv]
                for i, j in enumerate(que):
                    v = self.cipher.encrypt_block(xor(j, v))
                    result.append(v)
                return result, None
            else:
                for i, j in enumerate(que):
                    if i == 0:
                        v = j
                        continue    
                    nb = xor(self.cipher.decrypt_block(j), v)
                    result.append(nb)
                    v = j
                return result, None
                   
    def __ctr(self, data: list[bytes], decrypt: bool = False) -> tuple[list[bytes], list[dict] | None]:
        if decrypt:
            method = 'decrypt'
        else:
            method = 'encrypt'
        log = {'method': method,
                'mode': self.mode, 
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'input': [i.hex() for i in data],               
                'actions': []} 
        result = []
        xor = self.__xor
        if self.use_log:
            if not decrypt:
                nonce = os.urandom(8).ljust(16, b'\x00')
                log['nonce'] = nonce.hex()
                key_stream = []
                iterator = range(len(data))
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X10000000000000000:
                        raise OverflowError('ctr: counter overflow')                      
                    counter = i.to_bytes(16)
                    nk, block_log = self.cipher.encrypt_block(xor(counter, nonce))
                    key_stream.append(nk)
                    log['actions'].append(block_log)
                result = [nonce] + [xor(i, j) for i, j in zip(data, key_stream)]
                log['actions'].append({'method': 'xor', 'input': ([i.hex() for i in data], [i.hex() for i in key_stream]), 'output': [i.hex() for i in result[1:]]})
                log['actions'].append({'method': 'connect', 'input': ([result[0].hex()], [i.hex() for i in result[1:]]), 'output': [i.hex() for i in result]})
                log['output'] = [i.hex() for i in result]
                return result, log
            else:
                nonce, ct = data[0], data[1:]
                log['nonce'] = nonce.hex()
                key_stream = []
                iterator = range(len(data)-1)
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X10000000000000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(16)
                    nk, block_log = self.cipher.encrypt_block(xor(counter, nonce))
                    key_stream.append(nk)
                    log['actions'].append(block_log)           
                result = [xor(i, j) for i, j in zip(ct, key_stream)]
                log['actions'].append({'method': 'xor', 'input': ([i.hex() for i in data], [i.hex() for i in ct]), 'output': [i.hex() for i in result]})
                log['output'] = [i.hex() for i in result]
                return result, log
        else:
            if not decrypt:
                nonce = os.urandom(8).ljust(16, b'\x00')
                key_stream = []
                iterator = range(len(data))
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X10000000000000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(16)
                    key_stream.append(self.cipher.encrypt_block(xor(counter, nonce)))
                result = [nonce] + [xor(i, j) for i, j in zip(data, key_stream)]
                return result, None
            else:
                nonce, ct = data[0], data[1:]
                key_stream = []
                iterator = range(len(data)-1)
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X10000000000000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(16)
                    key_stream.append(self.cipher.encrypt_block(xor(counter, nonce)))
                result = [xor(i, j) for i, j in zip(ct, key_stream)]
                return result, None
                   
    def encrypt(self, data: bytes) -> bytes:
        blocks = split_data(add_padding(data))
        result, log = self.mode_func(blocks)
        if log:
            with open(f'{self.log_path}log{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.json', 'w') as f:
                json.dump(log, f)
        return merge_data(result)
        
    def decrypt(self, data: bytes) -> bytes:
        blocks = split_data(data)
        result, log = self.mode_func(blocks, decrypt = True)
        if log:
            with open(f'{self.log_path}log{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.json', 'w') as f:
                json.dump(log, f)
        return remove_padding(merge_data(result))
    
    @staticmethod
    def __xor(b1: bytes, b2: bytes):
        return bytes(i ^ j for i, j in zip(b1, b2))

def main():
    pass

if __name__ == "__main__":
    main()