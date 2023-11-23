import os
import csv
import cProfile
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import time


def read_csv(csv_file_path):
    data_set = []
    header = []
    try:
        if os.path.exists(csv_file_path):
            with open(csv_file_path, "r", encoding='utf-8') as file:
                reader = csv.reader(file)
                header = next(reader)
                for row in reader:
                    data_set.extend(row)
        else:
            raise FileNotFoundError(f"The file at path '{csv_file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred while reading the CSV file: {e}")
    return header, data_set


def encrypt_data(data_set):
    key = os.urandom(32) # 256 bit key
    iv = os.urandom(16)
    encrypted_data_set = []
    try:
        for data in data_set:
            pad = padding.PKCS7(256).padder()
            padded_data = pad.update(data.encode()) + pad.finalize()
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data_set.append(encrypted_data)
    except Exception as e:
        print(f"An error occurred while encrypting the data: {e}")
    return key, iv, encrypted_data_set


def decrypt_data(key, iv, encrypted_data_set):
    decrypted_data_set = []
    try:
        for encrypted_data in encrypted_data_set:
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()
            decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(256).unpadder()
            decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
            decrypted_data_set.append(decrypted_data.decode())
    except Exception as e:
        print(f"An error occurred while decrypting the data: {e}")
    return decrypted_data_set

def main():
    csv_file_path = "D:/Thesis Work/DataSet/diabetes_binary_health_indicators_BRFSS2015.csv"
    header, data_set = read_csv(csv_file_path)
    start_time = time.time()
    key, iv, encrypted_data_set = encrypt_data(data_set)
    decrypted_data_set = decrypt_data(key, iv, encrypted_data_set)

if __name__ == "__main__":
    main()
    cProfile.run('main()', sort='cumtime')
    
