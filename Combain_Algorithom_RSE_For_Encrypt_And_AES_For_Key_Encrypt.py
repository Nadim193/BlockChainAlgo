import csv
import os
import base64
import cProfile
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from concurrent.futures import ThreadPoolExecutor

def encrypt_data(data, public_key):
    if isinstance(data, str):
        data = data.encode()
    # Encrypt data using RSA
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Encode encrypted data in base64
    encoded_encrypted_data = base64.b64encode(encrypted_data)
    return encoded_encrypted_data

def decrypt_data(encoded_encrypted_data, private_key):
    # Decode encrypted data from base64
    encrypted_data = base64.b64decode(encoded_encrypted_data)
    # Decrypt data using RSA
    data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return data

def encrypt_aes(data, key):
    # Encrypt data using AES
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def decrypt_aes(encrypted_data, key):
    # Decrypt data using AES
    fernet = Fernet(key)
    data = fernet.decrypt(encrypted_data).decode()
    return data

def read_from_csv(file_path):
    # Read data from CSV file
    data = []
    header = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        header = next(reader)
        for row in reader:
            data.append(row)
    return data, header

def main():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    # Read data from CSV file
    file_path = 'D:/Thesis Work/DataSet/30-70cancerChdEtcTest.csv'
    
    data, header = read_from_csv(file_path)
    # Generate AES key
    password = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    aes_key = base64.urlsafe_b64encode(kdf.derive(password))

    # Encrypt data using RSA and AES
    encrypted_data = []
    for row in data:
        encrypted_row = []
        for item in row:
            encrypted_item = encrypt_data(item.encode(), public_key)
            encrypted_item = encrypt_aes(encrypted_item.decode(), aes_key)
            encrypted_row.append(encrypted_item)
        encrypted_data.append(encrypted_row)
        
    # Decrypt data using RSA and AES
    decrypted_data = []
    for row in encrypted_data:
        decrypted_row = []
        for item in row:
            item = decrypt_aes(item, aes_key)
            item = decrypt_data(item.encode(), private_key).decode()
            decrypted_row.append(item)
        decrypted_data.append(decrypted_row)


if __name__ == "__main__":
    main()
    
    cProfile.run('main()', sort='cumtime')
    
    # cProfile.run('decrypt_data(encoded_encrypted_data, private_key)', sort='cumtime')
    
    # cProfile.run('encrypt_aes(data, key)', sort='cumtime')
    
    # cProfile.run('decrypt_aes(encrypted_data, key)', sort='cumtime')