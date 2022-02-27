import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encode(message, key):
    aesCipher = Cipher(algorithms.AES(key),
        modes.ECB(),
        backend = default_backend())

    aesEncryptor = aesCipher.encryptor()
    aesDecryptor = aesCipher.decryptor()
    return aesEncryptor.update(bytes.fromhex(message))
    #print("Ciphertext: {}".format(aesEncryptor.update(message).hex()))

def decode(message, key):
    aesCipher = Cipher(algorithms.AES(key),
        modes.ECB(),
        backend = default_backend())

    aesDecryptor = aesCipher.decryptor()
    return aesDecryptor.update(bytes(message, 'utf-8'))

#print("Ciphertext: {} \nPlaintext: {}".format(message, aesDecryptor.update(message)))


if __name__ == "__main__":
    
    key = os.urandom(16)
    while True:
        print("\nAES-ECB Encoder Decoder")
        print("--------------------")
        print("\t1. Encode Message.")
        print("\t2. Decode Message.")
        print("\t3. Test nist kats.")
        print("\t4. Create new key.")
        print("\t5. Quit.\n")
        choice = input(">> ")
        print()

        if choice == '1':
            message = input("\nMessage to encode: ")
            #encode(message, key)
            print("Encoded Message: {}".format(
                encode(message, key)))

        elif choice == '2':
            message = input("\nMessage to decode: ")
            print("Decoded Message: {}".format(
                decode(message, key)))
        elif choice == '3':
            key = bytes.fromhex('00000000000000000000000000000000')

            aesCipher = Cipher(algorithms.AES(key),
            modes.ECB(),
            backend = default_backend())

            aesEncryptor = aesCipher.encryptor()
            aesDecryptor = aesCipher.decryptor()

            nist_kats = [
                    ('f34481ec3cc627bacd5dc3fb08f273e6',
                     '0336763e966d92595a567cc9ce537f5e'),
                    ('9798c4640bad75c7c3227db910174e72',
                     'a9a1631bf4996954ebc093957b234589'),
                    ('96ab5c2ff612d9dfaae8c31f30c42168',
                     'ff4f8391a6a40ca5b25d23bedd44a597'),
                    ('6a118a874519e64e9963798a503f1d35 ',
                     'dc43be40be0e53712f7e2bf5ca707209')
                    ]
            for index , kat in enumerate(nist_kats):
                plaintext, want_ciphertext = kat
                plaintext_bytes = bytes.fromhex(plaintext)
                ciphertext_bytes = aesEncryptor.update(plaintext_bytes)
                got_ciphertext = ciphertext_bytes.hex()
                
                result = "[PASS]" if got_ciphertext == want_ciphertext else "[FAIL]"
                print("Test {}. Expected {}, got {}. Result {}.".format(index, want_ciphertext, got_ciphertext, result))

        elif choice == '4':
            key = os.urandom(16)

        elif choice == '5':
            print("Terminaing. This program will self destruct in 5 seconds.\n")
            break

        else:
            print("Unknown option {}.".format(choice))
