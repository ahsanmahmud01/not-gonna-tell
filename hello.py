from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

def generate_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

def decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=ciphertext[:AES.block_size])
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext

def main():
    password = input("Enter password: ").encode()
    salt = get_random_bytes(AES.block_size)

    key = generate_key(password, salt)

    choice = input("Encrypt (E) or Decrypt (D)? ").upper()
    if choice == 'E':
        plaintext = input("Enter the text to encrypt: ").encode()
        ciphertext = encrypt(plaintext, key)
        print("Encrypted text:", ciphertext.hex())
    elif choice == 'D':
        encrypted_text_hex = input("Enter the encrypted text in hexadecimal format: ")
        ciphertext = bytes.fromhex(encrypted_text_hex)
        decrypted_text = decrypt(ciphertext, key)
        print("Decrypted text:", decrypted_text.decode())
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
