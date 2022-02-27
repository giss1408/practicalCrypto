from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import time, os

class AESCTRAlgoritm:
    def __init__(self):
        self.name = "AES-CTR"

    def get_cipher_pair(self):
        key = os.urandom(32)
        nonce = os.urandom(16)

        aes_context = Cipher(
            algorithms.AES(key),
            modes.CTR(nonce),
            backend=default_backend()
        )

        return aes_context.encryptor(), aes_context.decryptor()

class RSAEncryptor:
    def __init__(self, public_key, max_encrypt_size):
        self._public_key = public_key
        self._max_encrypt_size = max_encrypt_size

    def update(self, plaintext):
        ciphertext = b""
        for offset in range(0, len(plaintext),self._max_encrypt_size):
            ciphertext += self._public_key.encrypt(
                plaintext[offset:offset+self._max_encrypt_size],
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )                
            )
        return ciphertext

    def finalize(self):
        return b""


class RSADecryptor:
    def __init__(self, private_key, max_decrypt_size):
        self._private_key = private_key
        self._max_decrypt_size = max_decrypt_size

    def update(self, ciphertext):
        plaintext = b""
        for offset in range ( 0, len(ciphertext), self._max_decrypt_size):
            plaintext += self._private_key.decrypt(
                ciphertext[offset:offset+self._max_decrypt_size],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        return plaintext

    def finalize(self):
        return b""

class RSAAlgorithm:
    def __init__(self):
        self.name = "RSA Encryption"

    def get_cipher_pair(self):
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        max_plaintext_size = 190
        max_ciphertext_size = 256

        rsa_public_key = rsa_private_key.public_key()

        return (RSAEncryptor(rsa_public_key, max_plaintext_size), RSADecryptor(rsa_private_key, max_ciphertext_size))

