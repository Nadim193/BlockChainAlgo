import cProfile
import csv
import os
import time
import chardet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_csv_data(filename):
    data = []
    header = []
    with open(filename, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']
    with open(filename, 'r', encoding=encoding) as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        for row in reader:
            data.extend(row)
    return data, header


def aes_encrypt(key, iv, data_set):
    encrypted_data_set = []
    try:
        for data in data_set:
            # Pad the data to the block size of the cipher
            pad = padding.PKCS7(256).padder()
            padded_data = pad.update(data.encode()) + pad.finalize()

            # Create the cipher object
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()

            # Encrypt the padded data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Add the encrypted data to the list of encrypted data
            encrypted_data_set.append(encrypted_data)
    except Exception as e:
        print(f"An error occurred while encrypting the data: {e}")
    return encrypted_data_set


def aes_decrypt(key, iv, encrypted_data_set):
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


def rsa_encrypt(public_key, plaintext):
    encrypted_key = public_key.encrypt(
        plaintext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def rsa_decrypt(private_key, encrypted_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key


def main():
    # Load data from CSV file
    data, header = load_csv_data('D:/Thesis Work/DataSet/30-70cancerChdEtcTest.csv')

    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # AES encryption
    key = os.urandom(32)
    iv = os.urandom(16)

    encrypted_data_set = aes_encrypt(key, iv, data)

    # RSA encryption
    encrypted_key = rsa_encrypt(public_key, key)

    # RSA decryption
    decrypted_key = rsa_decrypt(private_key, encrypted_key)
    assert decrypted_key == key, 'Error: decrypted key does not match original key'

    # AES decryption
    decrypted_data_set = aes_decrypt(decrypted_key, iv, encrypted_data_set)
    
    

if __name__ == '__main__':
    main()
    
    cProfile.run('main()', sort='cumtime')

    
    
