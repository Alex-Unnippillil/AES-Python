# -*- coding: utf-8 -*-
"""
@author: Alex Unnippillil
"""

import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_password(length):
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+=<>?/"
    password = ""
    for _ in range(length):
        password += random.choice(characters)
    return password

def aes_encrypt(message, key):
    backend = default_backend()
    iv = random.getrandbits(128).to_bytes(16, "big")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(ciphertext, key):
    backend = default_backend()
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()
    return unpadded_message.decode()

def multiple_encryption(message, keys):
    encrypted_message = message
    for key in keys:
        if key.startswith('aes:'):
            key = key[4:]
            encrypted_message = aes_encrypt(encrypted_message, key)
        else:
            encrypted_message = encrypt_message(encrypted_message, int(key))
    return encrypted_message

def multiple_decryption(encrypted_message, keys):
    decrypted_message = encrypted_message
    for key in reversed(keys):
        if key.startswith('aes:'):
            key = key[4:]
            decrypted_message = aes_decrypt(decrypted_message, key)
        else:
            decrypted_message = decrypt_message(decrypted_message, int(key))
    return decrypted_message

def main():
    print("An AES Encryption Program!")

    while True:
        print("\nWhat would you like to do?")
        print("1. Generate a random password")
        print("2. Encrypt a message")
        print("3. Decrypt a message")
        print("4. Quit")

        choice = input("Enter your choice (1-4): ")

        if choice == "1":
            length = int(input("Enter the length of the password: "))
            password = generate_password(length)

            num_layers = random.randint(2, 5)
            encryption_keys = []
            for _ in range(num_layers):
                encryption_keys.append(str(random.randint(1, 26)))
            encryption_keys.append('aes:' + Fernet.generate_key().decode())

            encrypted_password = multiple_encryption(password, encryption_keys)

            print("Generated password:", password)
            print("Encrypted password:", encrypted_password)
            print("Encryption keys:", encryption_keys)

        elif choice == "2":
            message = input("Enter the message to encrypt: ")
            keys = []
            num_layers = int(input("Enter the number of encryption layers: "))

            for i in range(num_layers):
                key = input(f"Enter encryption key for layer {i+1}: ")
                keys.append(key)

            encrypted_message = multiple_encryption(message, keys)
            print("Encrypted message:", encrypted_message)

        elif choice == "3":
            encrypted_message = input("Enter the message to decrypt: ")
            keys = []

            num_layers = int(input("Enter the number of encryption layers: "))

            for i in range(num_layers):
                key = input(f"Enter decryption key for layer {i+1}: ")
                keys.append(key)

            decrypted_message = multiple_decryption(encrypted_message, keys)
            print("Decrypted message:", decrypted_message)

        elif choice == "4":
            print("Thank you for using the Fun Cybersecurity Program!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
