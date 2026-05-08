import os
from datetime import datetime
import json
from tqdm import tqdm
from .block_utils import add_padding, remove_padding, split_data, merge_data
from .configs import AESConfig
from .aes_core.cipher import CoreAES

class AES:
    """
    A high-level interface for AES, supporting multiple modes of operation.
    """
    def __init__(self, key: bytes, mode: str = 'ECB', config: AESConfig = AESConfig()):
        """
        Initializing class AES object.

        Arg:
            key (bytes): Key for the AES alogrithom(128, 192, 256 bits).
            mode (str): Block cipher mode of operation, ECB, CBC, CTR are supported.
            config (AESConfig): Configuration object defined in .configs. Refer to the AESConfig class for attribute details.
        """
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

    def __ecb(self, data: bytes, decrypt: bool = False) -> tuple[bytes, dict | None]:
        if decrypt:
            method = 'decrypt'
        else:
            method = 'encrypt'
        log = {'method': method,
                'mode': self.mode,
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'input': data.hex(),
                'actions': []}
        if not decrypt:
            data = add_padding(data)
        que = split_data(data)
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
            result = merge_data(result)
            if decrypt:
                result = remove_padding(result)
            log['output'] = [result.hex()]
            return result, log
        else:
            for i, j in enumerate(que):
                if not decrypt:
                    nb = self.cipher.encrypt_block(j)
                else:
                    nb = self.cipher.decrypt_block(j)
                result.append(nb)
            result = merge_data(result)
            if decrypt:
                result = remove_padding(result)
            return result, None

    def __cbc(self, data: bytes, decrypt: bool = False) -> tuple[bytes, dict | None]:
        if decrypt:
            method = 'decrypt'
        else:
            method = 'encrypt'
        log = {'method': method,
                'mode': self.mode,
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'input': data.hex(),
                'actions': []}
        if not decrypt:
            data = add_padding(data)
        que = split_data(data)
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
                result = merge_data(result)
                log['output'] = [result.hex()]
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
                result = remove_padding(merge_data(result))
                log['output'] = [result.hex()]
                return result, log
        else:
            if not decrypt:
                iv = os.urandom(16)
                v = iv
                result = [iv]
                for i, j in enumerate(que):
                    v = self.cipher.encrypt_block(xor(j, v))
                    result.append(v)
                return merge_data(result), None
            else:
                for i, j in enumerate(que):
                    if i == 0:
                        v = j
                        continue
                    nb = xor(self.cipher.decrypt_block(j), v)
                    result.append(nb)
                    v = j
                return remove_padding(merge_data(result)), None

    def __ctr(self, data: bytes, decrypt: bool = False) -> tuple[bytes, dict | None]:
        if decrypt:
            method = 'decrypt'
        else:
            method = 'encrypt'
        log = {'method': method,
                'mode': self.mode,
                'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'input': data.hex(),
                'actions': []}
        result = []
        data_len = len(data)
        xor = self.__xor
        if self.use_log:
            if not decrypt:
                nonce = os.urandom(12)
                log['nonce'] = nonce.hex()
                key_stream = []
                iterator = range((data_len//16)+int(data_len%16 != 0))
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X100000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(4)
                    nk, block_log = self.cipher.encrypt_block(nonce + counter)
                    key_stream.append(nk)
                    log['actions'].append(block_log)
                key_stream = merge_data(key_stream)[:data_len]
                result = nonce.rjust(16, b'\x00') + xor(data, key_stream)
                log['actions'].append({'method': 'xor', 'input': (data.hex(), key_stream.hex()), 'output': result[16:].hex()})
                log['actions'].append({'method': 'connect', 'input': (result[:16].hex(), result[16:].hex()), 'output': result.hex()})
                log['output'] = result.hex()
                return result, log
            else:
                nonce, ct = data[4:16], data[16:]
                log['nonce'] = nonce.hex()
                key_stream = []
                iterator = range((data_len//16)+int(data_len%16 != 0)-1)
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X100000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(4)
                    nk, block_log = self.cipher.encrypt_block(nonce + counter)
                    key_stream.append(nk)
                    log['actions'].append(block_log)
                key_stream = merge_data(key_stream)[:data_len]
                result = xor(ct, key_stream)
                log['actions'].append({'method': 'xor', 'input': (data.hex(), key_stream.hex()), 'output': result.hex()})
                log['output'] = result.hex()
                return result, log
        else:
            if not decrypt:
                nonce = os.urandom(12)
                key_stream = []
                iterator = range((data_len//16)+int(data_len%16 != 0))
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X100000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(4)
                    key_stream.append(self.cipher.encrypt_block(nonce + counter))
                result = nonce.rjust(16, b'\x00') + xor(data, merge_data(key_stream))
                return result, None
            else:
                nonce, ct = data[4:16], data[16:]
                key_stream = []
                iterator = range((data_len//16)+int(data_len%16 != 0)-1)
                if self.progress_bar:
                    iterator = tqdm(iterator)
                for i in iterator:
                    if i >= 0X100000000:
                        raise OverflowError('ctr: counter overflow')
                    counter = i.to_bytes(4)
                    key_stream.append(self.cipher.encrypt_block(nonce + counter))
                result = xor(ct, merge_data(key_stream))
                return result, None

    def encrypt(self, data: bytes) -> bytes:
        """encrypt bytes data"""
        result, log = self.mode_func(data)
        if log:
            with open(f'{self.log_path}log{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.json', 'w') as f:
                json.dump(log, f)
        return result

    def decrypt(self, data: bytes) -> bytes:
        """decrypt bytes data"""
        result, log = self.mode_func(data, decrypt = True)
        if log:
            with open(f'{self.log_path}log{datetime.now().strftime("%Y%m%d_%H%M%S_%f")}.json', 'w') as f:
                json.dump(log, f)
        return result

    def encrypt_block(self, data: bytes) -> bytes | tuple[bytes, dict]:
        """encrypt one block of bytes data (size = 16 bytes)"""
        return self.cipher.encrypt(data)

    def decrypt_block(self, data: bytes) -> bytes | tuple[bytes, dict]:
        """decrypt one block of bytes data (size = 16 bytes)"""
        return self.cipher.decrypt(data)

    @staticmethod
    def __xor(b1: bytes, b2: bytes):
        return bytes(i ^ j for i, j in zip(b1, b2))
