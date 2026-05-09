**_Warning: This implementation is intended for analysis and educational purpose and should not be used for real-world security._**

## About
- **Author:** shrimp2845  
- **Version:** 0.4.0
- **License:** MIT

A pure Python implementation of the Advanced Encryption Standard (AES) algorithm with support for multiple key sizes, configurable internal transformations, detailed logging, and multiple cipher modes of operation.

## Features
- AES-128/AES-192/AES-256 support
- ECB/CBC/CTR modes
- PKCS#7 padding
- Custom AES transformation configuration
- Custom S-Box support
- Encryption/decryption logging

## Project Structure
```

project_AES/
  ├── __init__.py
  ├── block_utils.py
  ├── configs.py
  ├── project_AES.py
  └── aes_core/
      ├── __init__.py
      ├── cipher.py
      ├── core_utils.py
      ├── key_expansion.py
      ├── math_utils.py
      └── round.py

```

## Installation
Requires Python 3.10+
```bash
pip install project-aes
```
or 

```bash
pip install tqdm
git clone https://github.com/shrimp2845-tw/project_AES.git
cd project_AES
```

## Quick Start
```python
from project_AES import AES
key = b"0123456789abcdef"
plaintext = b"hello world"
cipher = AES(key)
ciphertext = cipher.encrypt(plaintext)
print(ciphertext)
```

## Docs
```
class initialize
----------------------
from project_AES import AES
aes = AES(key, mode='ECB', config=None)

key -> bytes (16, 24 or 32 bytes)
Required. AES key for 128/192/256-bit encryption.
mode -> str (optional)
Block cipher mode of operation.
Supported: 'ECB', 'CBC', 'CTR'
Default: 'ECB'
config -> AESConfig (optional)
Advanced configuration. Default is AESConfig()


methods
----------------------
encrypt(data: bytes) -> bytes
decrypt(data: bytes) -> bytes
→ Encrypt/decrypt bytes data

encrypt_block(block: bytes) -> bytes
decrypt_block(block: bytes) -> bytes
→ single block (16 bytes) encryption/decryption
```
## Examples
This project includes three example scripts demonstrating different functionalities of the module:  

**​1.[File Cipher](https://github.com/shrimp2845-tw/project_AES/blob/main/examples/file_cipher.py)**: 
A script for encrypting and decrypting files using AES with various operation modes (ECB, CBC, CTR).  

**​2.[Avalanche Observation](https://github.com/shrimp2845-tw/project_AES/blob/main/examples/avalanche_observation.py)**: A script to observe the avalanche effect by testing how bit-flips in plaintext affect the ciphertext under different configurations.

**3.[Differential](https://github.com/shrimp2845-tw/project_AES/blob/main/examples/differential.py)**: A script constructs Difference Distribution Tables (DDT) to analyze the cryptographic strength of the S-Box (both standard and user defined).

### Samples
**1.File Cipher**:

You can try to decrypt [these examples](https://github.com/shrimp2845-tw/project_AES/tree/main/examples/test_files) by your self
 
- hina.png -> encrypt(key=gehenna, mode=ECB) -> hina.bin

- kayoko.jpg -> encrypt(key=cat, mode=CBC) -> kayoko.bin

- r18.gif -> encrypt(key=give you up, mode=CTR) -> r18.bin

(I originally wanted to use a picture of Shiina Mahiru, but I couldn’t find any good images under a cc license QAQ)

**2.Avalanche Observation**:

![Alt-text](https://raw.githubusercontent.com/shrimp2845-tw/project_AES/main/examples/test_files/avalanche_observation.png)

## Disclaimer

This implementation is intended for **analysis and educational purposes only**.  
It does **not guarantee cryptographic security** or **production-level performance efficiency**.  

Do not use this project in any environment that requires strong security assurances.

