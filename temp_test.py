from project_AES.aes_core.cipher import CoreAES

def test(key, pt, ct):
    print(30*'_')
    print('key:       ', key)
    print('plaintext: ', pt)
    print('ciphertext:', ct)
    c = CoreAES(bytes.fromhex(key))
    r1 = c.encrypt_block(bytes.fromhex(pt)).hex()
    r2 = c.decrypt_block(bytes.fromhex(ct)).hex()
    print('result:'+'\n'+r1+'\n'+r2)
    print('pass:', r1 == ct and r2 == pt)
    

def main():
    cases = [
    # AES-128
    ["2b7e151628aed2a6abf7158809cf4f3c",
    "3243f6a8885a308d313198a2e0370734",
    "3925841d02dc09fbdc118597196a0b32"],    
    # AES-192
    ["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "6bc1bee22e409f96e93d7e117393172a",
    "bd334f1d6e45f25ff712a214571fa5cc"],  
    # AES-256
    ["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "6bc1bee22e409f96e93d7e117393172a",
    "f3eed1bdb5d2a03c064b5a7e3db181f8"]]
    
    for k, pt, ct in cases:
        test(k, pt, ct)

if __name__ == "__main__":
    main()



