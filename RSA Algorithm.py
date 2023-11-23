import os
import hashlib
import csv
import cProfile
import shutil
import json
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature
import time


def read_csv_file(file_path):
    data_set = []
    header = []
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding='utf-8') as file:
                reader = csv.reader(file)
                header = next(reader)
                for row in reader:
                    data_set.extend(row)
        else:
            raise FileNotFoundError(f"The file at path '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred while reading the CSV file: {e}")
    
    return header, data_set


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=cryptography.hazmat.backends.default_backend()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def encrypt_data_set(data_set, public_key):
    encrypted_data_set = []
    try:
        for data in data_set:
            encrypted_data = public_key.encrypt(
                data.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=SHA256()),
                    algorithm=SHA256(),
                    label=None
                )
            )
            encrypted_data_set.append(encrypted_data)
    except Exception as e:
        print(f"An error occurred while encrypting the data: {e}")

    return encrypted_data_set


def decrypt_data_set(encrypted_data_set, private_key):
    decrypted_data_set = []
    try:
        for index in range(len(encrypted_data_set)):
            encrypted_data = encrypted_data_set[index]
            try:
                decrypted_data = private_key.decrypt(
                    encrypted_data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=SHA256()),
                        algorithm=SHA256(),
                        label=None
                    )
                )
                decrypted_data = decrypted_data.decode()
                decrypted_data_set.append(decrypted_data)
            except InvalidSignature as e:
                print(f"Error while decrypting data at index {index}: {e}")
    except Exception as e:
        print(f"An error occurred while decrypting data: {e}")
    
    return decrypted_data_set


def main():
    # Read CSV file
    csv_file_path = "D:/Thesis Work/DataSet/diabetes_binary_health_indicators_BRFSS2015.csv"
    header, data_set = read_csv_file(csv_file_path)

    # Generate RSA key pair
    private_key, public_key = generate_rsa_key_pair()

    # Encrypt the data before uploading to Azure Blob Storage
    encrypted_data_set = encrypt_data_set(data_set, public_key)

    # Decrypt the data after downloading from Azure Blob Storage
    decrypted_data_set = decrypt_data_set(encrypted_data_set, private_key)


if __name__ == "__main__":
    main()
    cProfile.run('main()', sort='cumtime')
    
