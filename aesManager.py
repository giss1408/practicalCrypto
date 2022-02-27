from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography. hazmat.primitives import padding
import os

class EncryptionManager:
    def __init__(self):
        self.key = os.urandom(32)
        self.iv = os.urandom(16)
        print("key: {} \nIV: {}".format(self.key.hex(), self.iv.hex()))

        aesContext = Cipher(algorithms.AES(self.key),
                            modes.CBC(self.iv),
                            backend = default_backend()
                            )

        self.encryptor = aesContext.encryptor()
        self.decryptor = aesContext.decryptor()
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def update_encryptor(self, plaintext):
        return self.encryptor.update(self.padder.update(plaintext))

    def finalize_encryptor(self):
        return self.encryptor.update(self.padder.finalize()) + self.encryptor.finalize()

    def update_decryptor(self, ciphertext):
        return self.unpadder.update(self.decryptor.update(ciphertext))

    def finalize_decryptor(self):
        return self.unpadder.update(self.decryptor.finalize()) + self.unpadder.finalize()

manager = EncryptionManager()

plaintexts = [
    b"SHORT",
    b"MEDIUM MEDIUM MEDIUM",
    b"LONG LONG LONG LONG LONG LONG",
    ] 

ciphertexts = []

for m in plaintexts:
    ciphertexts.append(manager.update_encryptor(m))
ciphertexts.append(manager.finalize_encryptor())
print("Ciphertext [{}]".format(','.join(x.hex() for x in ciphertexts)))

for c in ciphertexts:
    print("Recovered", manager.update_decryptor(c))

print("Recovered", manager.finalize_decryptor())

manager2 = EncryptionManager()
ciphertexts2 = []

for m in plaintexts:
    ciphertexts2.append(manager2.update_encryptor(m))
ciphertexts2.append(manager2.finalize_encryptor())
print("Ciphertext [{}]".format(','.join(x.hex() for x in ciphertexts2)))

for c in ciphertexts2:
    print("Recovered", manager2.update_decryptor(c))

print("Recovered", manager2.finalize_decryptor())
