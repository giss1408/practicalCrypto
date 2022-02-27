import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

key = os.urandom(16)
aesCipher = Cipher(algorithms.AES(key),
        modes.ECB(),
        backend = default_backend())

aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

def encode(message):
    return 

def decode(message, subst):
    return encode(message, subst)

if __name__ == "__main__":
    
    while True:
        print("\nAES-ECB Encoder Decoder")
        print("--------------------")
        print("\t1. Encode Message.")
        print("\t2. Decode Message.")
        print("\t5. Quit.\n")
        choice = input(">> ")
        print()

        if choice == '1':
            message = input("\nMessage to encode: ")
            print("Encoded Message: {}".format(
                encode(message.upper(), encoding)))

        elif choice == '2':
            message = input("\nMessage to decode: ")
            print("Decoded Message: {}".format(
                decode(message.upper(), decoding)))

        elif choice == '3':
            print("Terminaing. This program will self destruct in 5 seconds.\n")
            break

        else:
            print("Unknown option {}.".format(choice))