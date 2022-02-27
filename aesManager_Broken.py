from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography. hazmat.primitives import padding
import os

class EncryptionManager:
    def __init__(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        print("key: {} \nIV: {}".format(self.key.hex(), self.iv.hex()))

    def encrypt_message(self, message):
        aesCipher = Cipher(algorithms.AES(self.key),
                            modes.CBC(self.iv),
                            backend = default_backend()
                            )
        encryptor = aesCipher.encryptor()
        padder = padding.PKCS7(128).padder()

        padded_message = padder.update(message)
        padded_message += padder.finalize()
        ciphertext = encryptor.update(padded_message)
        ciphertext += encryptor.finalize()
        print()
        return ciphertext

    def decrypt_message(self, ciphertext):
        aesCipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(self.iv),
                backend = default_backend()
                )
        decryptor = aesCipher.decryptor()

        unpadder = padding.PKCS7(128).unpadder()

        padded_message = decryptor.update(ciphertext)
        padded_message += decryptor.finalize()
        message = unpadder.update(padded_message)
        message += unpadder.finalize()
        return message

manager = EncryptionManager()

plaintexts = [
        b"SHORT",
        b"MEDIUM MEDIUM MEDIUM",
        b"LONG LONG LONG LONG LONG LONG",
        ]
        
ciphertexts =[]

for m in plaintexts:
    ciphertexts.append(manager.encrypt_message(m))
print("Ciphertext [{}]".format(','.join(x.hex() for x in ciphertexts)))
for c in ciphertexts:
    print("Recovered", manager.decrypt_message(c))

ciphertexts2 =[]

for m in plaintexts:
    ciphertexts2.append(manager.encrypt_message(m))
print("Ciphertext [{}]".format(','.join(x.hex() for x in ciphertexts)))

for c in ciphertexts2:
    print("Recovered", manager.decrypt_message(c))



