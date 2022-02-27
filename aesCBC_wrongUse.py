import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

if __name__ == "__main__":
    
    key = os.urandom(32)
    iv = os.urandom(16)

    aesCipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend = default_backend()
            )

    aesEncryptor = aesCipher.encryptor()
    aesDecryptor = aesCipher.decryptor()

    padder = padding.PKCS7(128).padder()
    unpadder = padding.PKCS7(128).unpadder()

    plaintexts = [
        b"SHORT",
        b"MEDIUM MEDIUM MEDIUM",
        b"LONg LONG LONG LONg LONG LONG",
        ]

    ciphertexts = []

    for m in plaintexts:
        padded_messages = padder.update(m)
        ciphertexts.append(aesEncryptor.update(padded_messages))
    
    ciphertexts.append(aesEncryptor.update(padder.finalize()))
    print("Ciphertext [{}]".format(','.join(x.hex() for x in ciphertexts)))

    for c in ciphertexts:
        padded_message = aesDecryptor.update(c)
        print("recovered", unpadder.update(padded_message))
        

    print("recovered", unpadder.finalize())
